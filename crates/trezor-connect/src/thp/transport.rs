//! Packet transports for THP: UDP (emulator) and USB (physical device).
//!
//! THP frames travel as fixed 64-byte packets on both transports — one UDP
//! datagram or one USB interrupt transfer per packet. The channel state machine
//! upstairs neither knows nor cares which pipe the packets ride.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use rusb::{DeviceHandle, GlobalContext};

use crate::TrezorSignerError;

/// THP packet size on the wire (both UDP and USB).
pub(crate) const PACKET_LEN: usize = 64;

/// Default emulator UDP port.
pub(crate) const EMULATOR_PORT: u16 = 21324;

/// Trezor USB identity: VID/PID in firmware mode (Model T and the Safe family
/// share it), the WebUSB data interface, and its interrupt endpoint pair.
///
/// Defined by the firmware in
/// `vendor/trezor-firmware/core/embed/io/usb/usb_config.c`.
pub(crate) const TREZOR_VID_PID: (u16, u16) = (0x1209, 0x53C1);
const USB_CONFIG_ID: u8 = 0;
pub(crate) const USB_INTERFACE: u8 = 0;
const USB_CLASS_VENDOR_SPEC: u8 = 0xff;
const USB_ENDPOINT_OUT: u8 = 0x01;
const USB_ENDPOINT_IN: u8 = 0x81;

const USB_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Moves whole 64-byte THP packets to and from the device.
pub(crate) trait Transport: Send {
    fn send(&mut self, packet: &[u8]) -> Result<(), TrezorSignerError>;
    /// Wait up to `timeout` for one packet; `Ok(None)` on timeout.
    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TrezorSignerError>;
}

/// UDP loopback to the firmware emulator.
pub(crate) struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub(crate) fn connect(peer: SocketAddr) -> Result<Self, TrezorSignerError> {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| TrezorSignerError::Protocol(format!("bind UDP socket: {e}")))?;
        // Connecting the socket makes the kernel drop datagrams from any
        // other source (a stray localhost packet must not disturb the
        // session) and surfaces ICMP port-unreachable, so a dead emulator
        // reports "connection refused" instead of timing out.
        socket
            .connect(peer)
            .map_err(|e| TrezorSignerError::Protocol(format!("connect UDP socket: {e}")))?;
        Ok(UdpTransport { socket })
    }
}

impl Transport for UdpTransport {
    fn send(&mut self, packet: &[u8]) -> Result<(), TrezorSignerError> {
        log::trace!("> {}", hex::encode(packet));
        self.socket
            .send(packet)
            .map_err(|e| TrezorSignerError::Protocol(format!("UDP send: {e}")))?;
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TrezorSignerError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| TrezorSignerError::Protocol(format!("set timeout: {e}")))?;
        let mut buf = vec![0u8; PACKET_LEN];
        match self.socket.recv(buf.as_mut_slice()) {
            Ok(len) => {
                buf.truncate(len);
                log::trace!("< {}", hex::encode(&buf));
                Ok(Some(buf))
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(None),
            Err(e) => Err(TrezorSignerError::Protocol(format!("UDP recv: {e}"))),
        }
    }
}

/// A Trezor found on the USB bus.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UsbLocation {
    pub bus: u8,
    pub address: u8,
}

/// Enumerate Trezors in firmware mode. Matches VID/PID and requires the
/// vendor-specific WebUSB data interface, mirroring what python-trezor checks.
/// Enumeration failures are logged and yield an empty list — a missing libusb
/// backend must not break the emulator path.
pub(crate) fn scan_usb() -> Vec<UsbLocation> {
    let devices = match rusb::devices() {
        Ok(d) => d,
        Err(e) => {
            log::warn!("USB enumeration failed: {e}");
            return Vec::new();
        }
    };
    let mut found = Vec::new();
    for dev in devices.iter() {
        let Ok(desc) = dev.device_descriptor() else {
            continue;
        };
        if (desc.vendor_id(), desc.product_id()) != TREZOR_VID_PID {
            continue;
        }
        let has_data_interface = dev
            .config_descriptor(USB_CONFIG_ID)
            .ok()
            .and_then(|config| {
                config
                    .interfaces()
                    .find(|i| i.number() == USB_INTERFACE)
                    .and_then(|i| i.descriptors().next().map(|d| d.class_code()))
            })
            .is_some_and(|class| class == USB_CLASS_VENDOR_SPEC);
        if !has_data_interface {
            continue;
        }
        found.push(UsbLocation {
            bus: dev.bus_number(),
            address: dev.address(),
        });
    }
    found
}

/// USB interrupt pipe to a physical Trezor.
pub(crate) struct UsbTransport {
    handle: DeviceHandle<GlobalContext>,
}

impl UsbTransport {
    pub(crate) fn connect(location: UsbLocation) -> Result<Self, TrezorSignerError> {
        let dev = rusb::devices()
            .map_err(|e| TrezorSignerError::Protocol(format!("USB enumeration: {e}")))?
            .iter()
            .find(|d| d.bus_number() == location.bus && d.address() == location.address)
            .ok_or(TrezorSignerError::NoDevice)?;

        let handle = dev.open().map_err(|e| match e {
            rusb::Error::Access => TrezorSignerError::Client(
                "USB permission denied opening the Trezor — on Linux install the Trezor \
                 udev rules (https://trezor.io/learn/a/udev-rules), then replug the device"
                    .to_string(),
            ),
            other => TrezorSignerError::Protocol(format!("USB open: {other}")),
        })?;

        // Linux: the kernel HID driver may hold the interface; detach it while
        // we have it claimed. Unsupported elsewhere, hence the ignored result.
        let _ = handle.set_auto_detach_kernel_driver(true);

        handle.claim_interface(USB_INTERFACE).map_err(|e| match e {
            rusb::Error::Busy => TrezorSignerError::Client(
                "the Trezor is in use by another application — close Trezor Suite \
                 (or another wallet) and try again"
                    .to_string(),
            ),
            other => TrezorSignerError::Protocol(format!("USB claim interface: {other}")),
        })?;

        Ok(UsbTransport { handle })
    }
}

impl Transport for UsbTransport {
    fn send(&mut self, packet: &[u8]) -> Result<(), TrezorSignerError> {
        debug_assert_eq!(packet.len(), PACKET_LEN);
        log::trace!("> {}", hex::encode(packet));
        let written = self
            .handle
            .write_interrupt(USB_ENDPOINT_OUT, packet, USB_WRITE_TIMEOUT)
            .map_err(|e| TrezorSignerError::Protocol(format!("USB write: {e}")))?;
        // A partial interrupt transfer would corrupt THP framing undetected —
        // fail loudly instead (the debug_assert above vanishes in release).
        if written != packet.len() {
            return Err(TrezorSignerError::Protocol(format!(
                "USB short write: {written} of {} bytes",
                packet.len()
            )));
        }
        Ok(())
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TrezorSignerError> {
        let mut buf = vec![0u8; PACKET_LEN];
        match self
            .handle
            .read_interrupt(USB_ENDPOINT_IN, &mut buf, timeout)
        {
            Ok(len) => {
                buf.truncate(len);
                log::trace!("< {}", hex::encode(&buf));
                Ok(Some(buf))
            }
            Err(rusb::Error::Timeout) => Ok(None),
            Err(rusb::Error::NoDevice) => Err(TrezorSignerError::Client(
                "the Trezor was unplugged".to_string(),
            )),
            Err(e) => Err(TrezorSignerError::Protocol(format!("USB read: {e}"))),
        }
    }
}
