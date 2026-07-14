//! THP session client — ported from `vendor/trezor-thp/examples/host-cli/client.rs`.
//!
//! A small UDP-backed driver over the `trezor-thp` channel state machine:
//! `write`/`read` move framed packets with ACK handling, `call` does one
//! request/response round-trip by raw message type, and `call_pb` layers
//! protobuf encode/decode plus `ButtonRequest` auto-ack on top.

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use protobuf::{Enum, Message};
use trezor_thp::channel::PacketInResult;
use trezor_thp::error::TransportError;
use trezor_thp::{channel::buffered::Buffered, channel::host::Mux, Backend, ChannelIO};

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
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const PACKET_LEN: usize = 64;

const MESSAGE_TYPE_BUTTONREQUEST: u16 = 26;
const MESSAGE_TYPE_BUTTONACK: u16 = 27;

pub(crate) struct Client<C> {
    pub channel: Buffered<C>,
    pub device_properties: Vec<u8>,
    socket: UdpSocket,
    emu_addr: SocketAddr,
}

impl<B> Client<Mux<B>>
where
    B: Backend,
{
    pub fn open(emu_addr: SocketAddr, channel: Mux<B>) -> Result<Self, TrezorSignerError> {
        let mut channel = Buffered::new(channel);
        channel.set_packet_len(PACKET_LEN);
        let socket = UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| TrezorSignerError::Protocol(format!("bind UDP socket: {e}")))?;
        Ok(Client {
            channel,
            device_properties: Vec::new(),
            socket,
            emu_addr,
        })
    }
}

impl<C: ChannelIO> Client<C> {
    pub fn map<D>(self, func: impl FnOnce(C) -> D) -> Client<D> {
        Client {
            channel: self.channel.map(|c| Ok(func(c))).unwrap(),
            device_properties: self.device_properties,
            socket: self.socket,
            emu_addr: self.emu_addr,
        }
    }

    fn send_to(&mut self, buf: &[u8]) -> Result<(), TrezorSignerError> {
        log::trace!("> {}", hex::encode(buf));
        self.socket
            .send_to(buf, self.emu_addr)
            .map_err(|e| TrezorSignerError::Protocol(format!("UDP send: {e}")))?;
        Ok(())
    }

    fn recv_from(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TrezorSignerError> {
        self.socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| TrezorSignerError::Protocol(format!("set timeout: {e}")))?;
        let mut sockbuf = vec![0u8; PACKET_LEN];
        match self.socket.recv_from(sockbuf.as_mut_slice()) {
            Ok((reply_len, src_addr)) => {
                if src_addr != self.emu_addr {
                    return Err(TrezorSignerError::Protocol(format!(
                        "reply from unexpected address {src_addr}"
                    )));
                }
                sockbuf.truncate(reply_len);
                log::trace!("< {}", hex::encode(&sockbuf));
                Ok(Some(sockbuf))
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(None),
            Err(e) => Err(TrezorSignerError::Protocol(format!("UDP recv: {e}"))),
        }
    }

    fn write_ack(&mut self) -> Result<Vec<u8>, TrezorSignerError> {
        self.channel
            .packet_out()
            .map_err(|e| TrezorSignerError::Protocol(format!("packet_out: {e:?}")))
    }

    fn read_ack(&mut self, packet: &[u8]) -> Result<bool, TrezorSignerError> {
        let pir = self
            .channel
            .packet_in(packet)
            .check_failed()
            .map_err(|e| TrezorSignerError::Protocol(format!("packet_in: {e:?}")))?;
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
            .map_err(|e| TrezorSignerError::Protocol(format!("message_in: {e:?}")))?;

        let mut acked = false;
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
                        self.channel.message_retransmit().map_err(|e| {
                            TrezorSignerError::Protocol(format!("retransmit: {e:?}"))
                        })?;
                        break;
                    }
                    Some(packet) => {
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
                let Some(packet) = self.recv_from(READ_TIMEOUT)? else {
                    return Err(TrezorSignerError::Protocol(format!(
                        "timed out waiting for response after {READ_TIMEOUT:?}"
                    )));
                };
                let pir = self
                    .channel
                    .packet_in(&packet)
                    .check_failed()
                    .map_err(|e| TrezorSignerError::Protocol(format!("packet_in: {e:?}")))?;
                if let PacketInResult::TransportError { error } = &pir {
                    return Err(transport_err(error));
                }
                done = pir.got_message() || pir.got_channel();
                send_ack = !pir.got_channel();
            }
            result = Some(
                self.channel
                    .message_out()
                    .map_err(|e| TrezorSignerError::Protocol(format!("message_out: {e:?}")))?,
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
