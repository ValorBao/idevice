//! Byte stream of IPv6 packets carried in QUIC datagrams.
//!
//! The userspace TCP stack speaks a concatenated stream of IP packets. QUIC
//! delivers one packet per datagram, so this type translates between the two.

use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ControlGuard;

/// [`AsyncRead`] / [`AsyncWrite`] view of a [`super::QuicTunnel`].
///
/// Each `write` of a complete IPv6 packet becomes one QUIC datagram. Each
/// `read` yields bytes from the next IPv6 datagram. Datagrams that are not
/// IPv6 (the handshake MTU probe, for example) are discarded.
pub struct QuicPacketStream {
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    _control: ControlGuard,
    pending: Vec<u8>,
    pending_pos: usize,
    write_buf: Vec<u8>,
}

impl std::fmt::Debug for QuicPacketStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicPacketStream")
            .field("buffered_read", &(self.pending.len() - self.pending_pos))
            .field("buffered_write", &self.write_buf.len())
            .finish_non_exhaustive()
    }
}

impl QuicPacketStream {
    pub(crate) fn from_parts(
        connection: quinn::Connection,
        endpoint: quinn::Endpoint,
        control: ControlGuard,
    ) -> Self {
        Self {
            connection,
            _endpoint: endpoint,
            _control: control,
            pending: Vec::new(),
            pending_pos: 0,
            write_buf: Vec::new(),
        }
    }

    fn fill_from_pending(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.pending_pos >= self.pending.len() {
            return false;
        }
        let available = self.pending.len() - self.pending_pos;
        let n = available.min(buf.remaining());
        buf.put_slice(&self.pending[self.pending_pos..self.pending_pos + n]);
        self.pending_pos += n;
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        true
    }
}

impl AsyncRead for QuicPacketStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        if this.fill_from_pending(buf) {
            return Poll::Ready(Ok(()));
        }

        let connection = this.connection.clone();
        loop {
            let incoming = std::pin::pin!(connection.read_datagram());
            match incoming.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) if connection_closed(&error) => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Err(io::Error::new(ErrorKind::ConnectionReset, error)));
                }
                Poll::Ready(Ok(datagram)) => {
                    if datagram.first().is_none_or(|byte| byte >> 4 != 6) {
                        log::debug!("dropping non-IPv6 quic datagram ({} bytes)", datagram.len());
                        continue;
                    }
                    let n = datagram.len().min(buf.remaining());
                    buf.put_slice(&datagram[..n]);
                    if n < datagram.len() {
                        this.pending.extend_from_slice(&datagram[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for QuicPacketStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_buf.extend_from_slice(buf);
        match flush_packets(&this.connection, &mut this.write_buf) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Poll::Ready(flush_packets(&this.connection, &mut this.write_buf))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

fn flush_packets(connection: &quinn::Connection, buf: &mut Vec<u8>) -> io::Result<()> {
    while let Some(packet) = pop_ipv6_packet(buf)? {
        if let Err(error) = connection.send_datagram(Bytes::copy_from_slice(&packet)) {
            let mut restored = packet;
            restored.append(buf);
            *buf = restored;
            return Err(io::Error::new(ErrorKind::BrokenPipe, error));
        }
    }
    Ok(())
}

fn connection_closed(error: &quinn::ConnectionError) -> bool {
    matches!(
        error,
        quinn::ConnectionError::LocallyClosed | quinn::ConnectionError::ApplicationClosed(_)
    )
}

/// Removes one complete IPv6 packet from the front of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet contain a full packet.
pub(crate) fn pop_ipv6_packet(buf: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] >> 4 != 6 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "quic tunnel packet is not IPv6",
        ));
    }
    if buf.len() < 40 {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let total = 40 + payload_len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(buf.drain(..total).collect()))
}

#[cfg(test)]
mod tests {
    use super::pop_ipv6_packet;

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 40 + payload.len()];
        bytes[0] = 0x60;
        let len = (payload.len() as u16).to_be_bytes();
        bytes[4] = len[0];
        bytes[5] = len[1];
        bytes[6] = 59;
        bytes[40..].copy_from_slice(payload);
        bytes
    }

    #[test]
    fn splits_concatenated_ipv6_packets() {
        let first = packet(b"one");
        let second = packet(b"two");
        let mut buf = first.clone();
        buf.extend_from_slice(&second[..10]);
        assert_eq!(pop_ipv6_packet(&mut buf).unwrap(), Some(first));
        assert!(pop_ipv6_packet(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&second[10..]);
        assert_eq!(pop_ipv6_packet(&mut buf).unwrap(), Some(second));
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_non_ipv6() {
        let mut buf = vec![0x45, 0, 0, 20];
        assert!(pop_ipv6_packet(&mut buf).is_err());
    }
}
