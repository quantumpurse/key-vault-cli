//! THP session client — ported from
//! `vendor/trezor-firmware/rust/trezor-thp/examples/host-cli/client.rs`.
//!
//! A small transport-agnostic driver over the `trezor-thp` channel state
//! machine: `write`/`read` move framed packets with ACK handling, `call` does
//! one request/response round-trip by raw message type, and `call_pb` layers
//! protobuf encode/decode plus `ButtonRequest` auto-ack on top. The packets
//! ride whatever [`Transport`] the session was opened with (emulator UDP or
//! physical USB).

use std::time::Duration;

use protobuf::{Enum, Message};
use trezor_thp::channel::PacketInResult;
use trezor_thp::error::TransportError;
use trezor_thp::{channel::buffered::Buffered, channel::host::Mux, Backend, ChannelIO};

use crate::thp::transport::{Transport, PACKET_LEN};
use crate::TrezorSignerError;

/// Turn a device-sent transport error into a helpful message.
fn transport_err(error: &TransportError) -> TrezorSignerError {
    match error {
        TransportError::DeviceLocked => TrezorSignerError::Client(
            "the Trezor is locked — unlock it on the device, then try again".to_string(),
        ),
        other => TrezorSignerError::Protocol(format!("transport error: {}", other.as_str())),
    }
}

const ACK_TIMEOUT: Duration = Duration::from_secs(1);
/// Give up after this many consecutive silent [`ACK_TIMEOUT`]s while waiting
/// for a transport-level ACK. The firmware's wire task ACKs on packet receipt
/// — before any processing or user interaction — so a live peer answers
/// within milliseconds; sustained silence means the peer is gone (dead
/// emulator port, or a device wedged while still enumerated). Giving up is
/// benign: nothing has been signed or broadcast, the user just reconnects.
const MAX_SILENT_RETRANSMITS: u32 = 10;
/// Default per-message read timeout. Generous because several protocol steps
/// legitimately wait on the user (on-device confirmations, code entry).
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Read timeout for the very first packet (channel allocation). A live device
/// or emulator answers it within milliseconds and no user interaction is
/// involved, so a short bound turns "nothing is listening" into a fast error
/// instead of a full [`READ_TIMEOUT`] stall.
pub(crate) const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Read timeout for the Noise handshake steps. Because we ask the device to
/// unlock itself (see `request_channel` in `thp::ThpSession::connect`), a
/// locked device holds its handshake reply until the user has typed their PIN
/// on the device — which can take considerably longer than the confirmations
/// [`READ_TIMEOUT`] is sized for.
///
/// This only bounds *silence*: a cancelled PIN, an unplugged cable, or any
/// device-sent error arrives immediately and is not waited out. So it is
/// sized for a user entering a PIN, not for detecting failure — and kept
/// bounded so a wedged device cannot park the caller forever.
pub(crate) const UNLOCK_TIMEOUT: Duration = Duration::from_secs(180);

// Wire message-type ids, derived from the generated protobuf enum so they
// cannot drift from the firmware's `messages.proto`.
const MESSAGE_TYPE_FAILURE: u16 = trezor_client::protos::MessageType::MessageType_Failure as u16;
const MESSAGE_TYPE_BUTTONREQUEST: u16 =
    trezor_client::protos::MessageType::MessageType_ButtonRequest as u16;
const MESSAGE_TYPE_BUTTONACK: u16 =
    trezor_client::protos::MessageType::MessageType_ButtonAck as u16;

pub(crate) struct Client<C> {
    pub channel: Buffered<C>,
    pub device_properties: Vec<u8>,
    transport: Box<dyn Transport>,
    read_timeout: Duration,
}

impl<B> Client<Mux<B>>
where
    B: Backend,
{
    pub fn open(transport: Box<dyn Transport>, channel: Mux<B>) -> Self {
        let mut channel = Buffered::new(channel);
        channel.set_packet_len(PACKET_LEN);
        Client {
            channel,
            device_properties: Vec::new(),
            transport,
            read_timeout: READ_TIMEOUT,
        }
    }
}

impl<C: ChannelIO> Client<C> {
    /// Transition the channel to a new state, propagating any failure. Used for
    /// the fallible `complete` steps of the handshake. (`trezor_thp::Error` does
    /// not implement `Debug`/`Display` in release builds, so it is discarded.)
    pub fn try_map<D>(
        self,
        func: impl FnOnce(C) -> Result<D, trezor_thp::Error>,
    ) -> Result<Client<D>, TrezorSignerError> {
        let channel = self
            .channel
            .map(func)
            .map_err(|_| TrezorSignerError::Protocol("THP channel transition failed".into()))?;
        Ok(Client {
            channel,
            device_properties: self.device_properties,
            transport: self.transport,
            read_timeout: self.read_timeout,
        })
    }

    /// Set the timeout for waiting on the device's next reply packet.
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        self.read_timeout = timeout;
    }

    fn send_to(&mut self, buf: &[u8]) -> Result<(), TrezorSignerError> {
        self.transport.send(buf)
    }

    fn recv_from(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TrezorSignerError> {
        self.transport.recv(timeout)
    }

    fn write_ack(&mut self) -> Result<Vec<u8>, TrezorSignerError> {
        self.channel
            .packet_out()
            .map_err(|_| TrezorSignerError::Protocol("THP packet_out failed".into()))
    }

    fn read_ack(&mut self, packet: &[u8]) -> Result<bool, TrezorSignerError> {
        let pir = self
            .channel
            .packet_in(packet)
            .check_failed()
            .map_err(|_| TrezorSignerError::Protocol("THP packet_in failed".into()))?;
        if let PacketInResult::TransportError { error } = &pir {
            return Err(transport_err(error));
        }
        Ok(pir.got_ack())
    }

    pub fn write(
        &mut self,
        sid: u8,
        message_type: u16,
        message: &[u8],
    ) -> Result<(), TrezorSignerError> {
        self.channel
            .message_in(sid, message_type, message)
            .map_err(|_| TrezorSignerError::Protocol("THP message_in failed".into()))?;

        let mut acked = false;
        let mut silent_retransmits = 0u32;
        while !acked {
            while self.channel.packet_out_ready() {
                let packet = self.write_ack()?;
                self.send_to(&packet)?;
            }
            // Only true if channel ID is not known, otherwise wait for an ACK.
            if self.channel.message_in_ready() {
                break;
            }
            while !acked {
                match self.recv_from(ACK_TIMEOUT)? {
                    None => {
                        silent_retransmits += 1;
                        if silent_retransmits >= MAX_SILENT_RETRANSMITS {
                            return Err(TrezorSignerError::Client(
                                "the Trezor stopped responding — reconnect and try again"
                                    .to_string(),
                            ));
                        }
                        self.channel.message_retransmit().map_err(|_| {
                            TrezorSignerError::Protocol("THP retransmit failed".into())
                        })?;
                        break;
                    }
                    Some(packet) => {
                        // Any packet proves the peer is alive; only count
                        // uninterrupted silence.
                        silent_retransmits = 0;
                        acked = self.read_ack(&packet)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn read(&mut self) -> Result<(u8, u16, Vec<u8>), TrezorSignerError> {
        let mut result: Option<(u8, u16, Vec<u8>)> = None;
        let mut send_ack = true;
        while result.is_none() {
            let mut done = false;
            while !done {
                let Some(packet) = self.recv_from(self.read_timeout)? else {
                    return Err(TrezorSignerError::Timeout(self.read_timeout));
                };
                let pir = self
                    .channel
                    .packet_in(&packet)
                    .check_failed()
                    .map_err(|_| TrezorSignerError::Protocol("THP packet_in failed".into()))?;
                if let PacketInResult::TransportError { error } = &pir {
                    return Err(transport_err(error));
                }
                done = pir.got_message() || pir.got_channel();
                send_ack = !pir.got_channel();
            }
            result = Some(
                self.channel
                    .message_out()
                    .map_err(|_| TrezorSignerError::Protocol("THP message_out failed".into()))?,
            );
        }
        if send_ack {
            let packet = self.write_ack()?;
            self.send_to(&packet)?;
        }
        result.ok_or_else(|| TrezorSignerError::Protocol("no message".to_string()))
    }

    /// One raw request/response round-trip by numeric message type.
    pub fn call(
        &mut self,
        message_type: u16,
        message: &[u8],
    ) -> Result<(u16, Vec<u8>), TrezorSignerError> {
        let session_id = 0;
        self.write(session_id, message_type, message)?;
        let (sid, reply_type, reply) = self.read()?;
        if sid != session_id {
            return Err(TrezorSignerError::Protocol(format!(
                "unexpected session id {sid}"
            )));
        }
        Ok((reply_type, reply))
    }

    pub fn write_pb(
        &mut self,
        sid: u8,
        message_type: impl Enum,
        message: impl Message,
    ) -> Result<(), TrezorSignerError> {
        let message_type: u16 = message_type
            .value()
            .try_into()
            .map_err(|_| TrezorSignerError::Protocol("message type out of range".to_string()))?;
        let bytes = message
            .write_to_bytes()
            .map_err(|e| TrezorSignerError::Protocol(format!("encode: {e}")))?;
        self.write(sid, message_type, &bytes)
    }

    /// Send a protobuf message and read a typed reply, auto-acking any
    /// `ButtonRequest` the device raises while it waits for the user.
    pub fn call_pb<T: Message, E: Enum>(
        &mut self,
        message_type: E,
        message: impl Message,
        expected_reply_type: E,
    ) -> Result<T, TrezorSignerError> {
        self.write_pb(0, message_type, message)?;
        let (mut reply_type, mut reply) = {
            let (_sid, mt, m) = self.read()?;
            (mt, m)
        };
        while reply_type == MESSAGE_TYPE_BUTTONREQUEST {
            self.write(0, MESSAGE_TYPE_BUTTONACK, &[])?;
            log::debug!("confirm on device...");
            let (_sid, mt, m) = self.read()?;
            reply_type = mt;
            reply = m;
        }
        let expected: u16 = expected_reply_type
            .value()
            .try_into()
            .map_err(|_| TrezorSignerError::Protocol("expected type out of range".to_string()))?;
        if reply_type == MESSAGE_TYPE_FAILURE && reply_type != expected {
            let msg = trezor_client::protos::Failure::parse_from_bytes(&reply)
                .ok()
                .map(|f| f.message().to_string())
                .unwrap_or_default();
            return Err(TrezorSignerError::Client(format!(
                "device rejected the request: {msg}"
            )));
        }
        if reply_type != expected {
            return Err(TrezorSignerError::Protocol(format!(
                "expected reply type {expected}, got {reply_type}"
            )));
        }
        T::parse_from_bytes(&reply)
            .map_err(|e| TrezorSignerError::Protocol(format!("decode reply: {e}")))
    }

    /// Send a raw-typed request and read a raw reply, auto-acking `ButtonRequest`.
    /// Used for CKB messages, whose protobuf types live in `trezor-client`.
    pub fn call_raw(
        &mut self,
        message_type: u16,
        message: &[u8],
    ) -> Result<(u16, Vec<u8>), TrezorSignerError> {
        self.write(0, message_type, message)?;
        let (mut reply_type, mut reply) = {
            let (_sid, mt, m) = self.read()?;
            (mt, m)
        };
        while reply_type == MESSAGE_TYPE_BUTTONREQUEST {
            self.write(0, MESSAGE_TYPE_BUTTONACK, &[])?;
            log::debug!("confirm on device...");
            let (_sid, mt, m) = self.read()?;
            reply_type = mt;
            reply = m;
        }
        Ok((reply_type, reply))
    }
}
