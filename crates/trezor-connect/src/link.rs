//! Device-presence probing and the session guard that keeps it honest.
//!
//! The host holds no standing connection — every operation opens a THP session
//! and drops it — so "is the device there?" has to be asked, not remembered.
//! [`probe_link`] answers it in about a millisecond without speaking THP, so it
//! is cheap enough to poll and never raises a prompt on the device.
//!
//! Probing and real work both want the same USB interface, so they are
//! serialized by [`session_guard`]: an open session holds it for its whole
//! lifetime, and the probe reports [`DeviceStatus::Working`] rather than
//! contending. Without that, a probe's momentary claim could make the user's
//! transfer fail with "the Trezor is in use by another application" — pointing
//! at Trezor Suite when the culprit was our own status indicator.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use crate::thp::transport::{scan_usb, EMULATOR_PORT, TREZOR_VID_PID, USB_INTERFACE};

/// Serializes everything that touches the device. Held for the lifetime of a
/// [`crate::TrezorSession`]; `try_lock`ed by the probe.
static DEVICE_GUARD: Mutex<()> = Mutex::new(());

/// How long an operation waits for the guard before giving up. Sized to cover a
/// probe's claim (sub-millisecond) with room to spare, while staying far below
/// the point where a caller would think the app had hung — an operation must
/// never queue behind a long signing session, it must say so instead.
const GUARD_WAIT: Duration = Duration::from_millis(500);

/// Emulator liveness probe timeout. Loopback, so a live emulator answers
/// immediately; this only bounds the silent case.
const PING_TIMEOUT: Duration = Duration::from_millis(200);

/// Datagrams sent before concluding the emulator is gone.
///
/// `PING_ATTEMPTS * PING_TIMEOUT` must stay below [`GUARD_WAIT`]: the probe
/// holds the guard for that whole span, and an operation starting inside it
/// would otherwise time out and blame a nonexistent other operation. Losing a
/// retry costs little, because the UI already requires several consecutive
/// failures before it reports trouble.
const PING_ATTEMPTS: u32 = 2;

/// What the host can tell about the device without talking to it.
///
/// Deliberately smaller than Trezor Suite's status taxonomy: Suite learns
/// lock/firmware/session state from a bridge daemon that pushes events, which
/// we have no equivalent of. Everything here is derived from a USB enumeration
/// plus a claim attempt, so it reports *availability*, never readiness —
/// whether the device is unlocked is only knowable by starting a handshake,
/// which prompts the user and therefore cannot be polled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    /// A Trezor is on the USB bus and its interface is free to claim.
    Linked,
    /// No USB device, but the emulator answered on its UDP port.
    Emulator,
    /// A Trezor is present but another application holds its interface.
    Busy,
    /// Nothing found on USB, and no emulator answering.
    Absent,
    /// One of our own sessions is open; the probe stood aside.
    Working,
}

impl DeviceStatus {
    /// True when an operation could plausibly start right now.
    pub fn is_available(self) -> bool {
        matches!(self, DeviceStatus::Linked | DeviceStatus::Emulator)
    }
}

/// Take the device guard for the lifetime of a session, waiting up to
/// [`GUARD_WAIT`] so a probe's momentary claim never fails a real operation.
///
/// Returns `None` if another session still holds it — the caller should report that
/// as "busy with another operation" rather than block, since the holder may be
/// waiting on a human at the device.
pub(crate) fn acquire_session_guard() -> Option<MutexGuard<'static, ()>> {
    let deadline = Instant::now() + GUARD_WAIT;
    loop {
        if let Some(guard) = try_take_guard() {
            return Some(guard);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Take the guard if it is free, recovering from poisoning.
///
/// A panic while a session was open poisons the mutex, but this guard protects
/// no data — only exclusivity — so the poison carries no meaning once the
/// panicking thread is gone. It must be cleared rather than merely stepped
/// over: a caller that treats `Poisoned` as "not available" would do so
/// forever, since poisoning is sticky, and the status readout would sit at
/// `Working` until the process restarted.
fn try_take_guard() -> Option<MutexGuard<'static, ()>> {
    match DEVICE_GUARD.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(p)) => {
            DEVICE_GUARD.clear_poison();
            Some(p.into_inner())
        }
        Err(TryLockError::WouldBlock) => None,
    }
}

/// Ask what the device is doing, without speaking THP and without prompting.
///
/// Costs a USB enumeration plus at most one claim/release, so it is safe to
/// call on a short cadence. Never runs while one of our sessions is open.
pub fn probe_link() -> DeviceStatus {
    let Some(_guard) = try_take_guard() else {
        // A session holds it, so the device is ours and busy.
        return DeviceStatus::Working;
    };

    if std::env::var_os("QPV2_TREZOR_EMULATOR").is_none() {
        if let Some(loc) = scan_usb().into_iter().next() {
            return probe_usb(loc.bus, loc.address);
        }
    }

    if emulator_listening() {
        DeviceStatus::Emulator
    } else {
        DeviceStatus::Absent
    }
}

/// Claim the interface and release it immediately. Claiming is the only way to
/// learn whether another application already owns it — enumeration alone cannot
/// tell, which is exactly the case where the user has Trezor Suite open.
fn probe_usb(bus: u8, address: u8) -> DeviceStatus {
    let Ok(devices) = rusb::devices() else {
        return DeviceStatus::Absent;
    };
    let Some(dev) = devices.iter().find(|d| {
        d.bus_number() == bus
            && d.address() == address
            && d.device_descriptor()
                .map(|desc| (desc.vendor_id(), desc.product_id()) == TREZOR_VID_PID)
                .unwrap_or(false)
    }) else {
        return DeviceStatus::Absent;
    };

    match dev.open() {
        Ok(handle) => {
            let _ = handle.set_auto_detach_kernel_driver(true);
            match handle.claim_interface(USB_INTERFACE) {
                Ok(()) => {
                    // Release at once: this was a question, not a session.
                    let _ = handle.release_interface(USB_INTERFACE);
                    DeviceStatus::Linked
                }
                // The device is plainly there, so every failure to claim it is
                // reported as busy rather than absent. `Access` is the
                // interesting one: on macOS an exclusively-claimed interface
                // surfaces as `Access` rather than `Busy`, and on Linux it means
                // the udev rules are missing — a real reconnect attempt then
                // produces the precise message, which a status dot cannot.
                Err(_) => DeviceStatus::Busy,
            }
        }
        Err(_) => DeviceStatus::Busy,
    }
}

/// Is an emulator listening on the wire port?
///
/// Answers *listening*, not *responsive*, and the distinction matters: the
/// emulator only serves `PINGPING` while a firmware task is awaiting wire input
/// (`usb_emulated_poll_read`, gated on `read_awaited`). Sitting at the
/// lockscreen nothing awaits it, so a perfectly healthy emulator never answers
/// — reporting that as "offline" would raise a red alarm over a device that is
/// merely locked.
///
/// So silence is not the test. A connected UDP socket surfaces ICMP
/// port-unreachable as `ConnectionRefused`, which *is* proof nothing is bound;
/// a timeout only proves nobody dequeued the datagram. Connecting the socket is
/// what makes that error reach us at all — an unconnected socket discards it.
///
/// Note the emulator's socket replies to whoever sent last, so any traffic here
/// briefly redirects its replies to us. That is why this only runs under the
/// device guard: with no session of ours open, there are no replies to steal.
fn emulator_listening() -> bool {
    let Ok(socket) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    if socket.set_read_timeout(Some(PING_TIMEOUT)).is_err() {
        return false;
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], EMULATOR_PORT));
    if socket.connect(addr).is_err() {
        return false;
    }
    let mut buf = [0u8; 8];

    for _ in 0..PING_ATTEMPTS {
        if socket.send(b"PINGPING").is_err() {
            // A refusal on send is the same verdict as one on receive.
            return false;
        }
        match socket.recv(&mut buf) {
            // Answered: awake and serving the wire.
            Ok(8) if &buf == b"PONGPONG" => return true,
            Ok(_) => continue,
            Err(e) => match e.kind() {
                // Nothing is bound to the port — genuinely gone.
                std::io::ErrorKind::ConnectionRefused => return false,
                // Bound but nobody dequeued it. Locked at the lockscreen, or
                // busy inside a long computation; either way it is there.
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    return true;
                }
                _ => return false,
            },
        }
    }
    false
}
