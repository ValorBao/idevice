//! Remote Pairing QUIC tunnel.
//!
//! iOS 17 through 18.1 can open a CoreDevice tunnel listener over QUIC.
//! [`RemotePairingSession::pair_setup`] runs the first-time trust dialog and
//! returns a host record. [`RemotePairingSession::pair_verify`] reuses that
//! record, then the session asks the device to `createListener`.
//! [`QuicTunnel::connect`] attaches to the UDP port that request returns.
//! [`QuicIdentity::listener_request`] is the body of that request.
//!
//! The CDTunnel handshake travels on a bidirectional QUIC stream. IPv6 packets
//! travel in QUIC datagrams. [`QuicTunnel::into_packet_stream`] presents those
//! packets as a byte stream, and — with the `tunnel_tcp_stack` feature —
//! [`QuicTunnel::into_adapter`] hands that stream to the userspace TCP stack.
//!
//! iOS 18.2 removed the QUIC listener. Later releases use a TCP tunnel with
//! TLS 1.2 PSK instead.
//!
//! # Example
//! ```
//! use idevice::quic::QuicIdentity;
//!
//! let identity = QuicIdentity::generate()?;
//! let request = identity.listener_request();
//! assert_eq!(
//!     request["request"]["_0"]["createListener"]["transportProtocolType"].as_str(),
//!     Some("quic")
//! );
//! # Ok::<(), idevice::IdeviceError>(())
//! ```

mod identity;
mod opack;
mod pairing;
mod srp;
mod stream;
mod tlv;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rustls::{
    DigitallySignedStruct,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    IdeviceError,
    core_device_proxy::{CDTunnelPacket, HandshakeResponse},
    util::{self, crypto_provider},
};

pub use identity::QuicIdentity;
pub use pairing::{PairSetupOptions, PairingRecord, RemotePairingSession};
pub use stream::QuicPacketStream;

/// ALPN announced by Apple's Remote Pairing QUIC listener.
pub const ALPN_PROTOCOL: &[u8] = b"RemotePairingTunnelProtocol";

/// IP MTU requested in the CDTunnel handshake.
///
/// Matches the value pymobiledevice3 sends for QUIC tunnels.
pub const REQUESTED_MTU: u32 = 1420;

/// Datagram payload cap advertised to the peer.
pub const MAX_DATAGRAM_SIZE: usize = 14_000;

/// How long the QUIC connection may sit idle before it is closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

const MTU_PROBE_LEN: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Options for [`QuicTunnel::connect`].
#[derive(Debug, Clone)]
pub struct QuicTunnelOptions {
    /// CDTunnel `mtu` sent to the device. Defaults to [`REQUESTED_MTU`].
    pub requested_mtu: u32,
    /// QUIC idle timeout. A keep-alive is sent at half this interval.
    pub idle_timeout: Duration,
    /// TLS server name sent as SNI. The certificate is not authenticated.
    pub server_name: String,
}

impl Default for QuicTunnelOptions {
    fn default() -> Self {
        Self {
            requested_mtu: REQUESTED_MTU,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            server_name: "localhost".to_string(),
        }
    }
}

/// Aborts the CDTunnel control-stream task when the tunnel is dropped.
pub(crate) struct ControlGuard {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ControlGuard {
    fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }
}

impl Drop for ControlGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Established Remote Pairing QUIC tunnel.
///
/// The [`quinn::Endpoint`] is kept alive for the life of the tunnel. Dropping
/// the tunnel closes the QUIC connection.
pub struct QuicTunnel {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    control: ControlGuard,
    handshake: HandshakeResponse,
}

impl std::fmt::Debug for QuicTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTunnel")
            .field("server_address", &self.handshake.server_address)
            .field("server_rsd_port", &self.handshake.server_rsd_port)
            .field("client_address", &self.handshake.client_parameters.address)
            .finish_non_exhaustive()
    }
}

impl QuicTunnel {
    /// Connects to a QUIC tunnel listener and completes the CDTunnel handshake.
    ///
    /// `identity` must be the same key that was advertised in `createListener`.
    /// `addr` is the device address plus the UDP port from that response.
    /// Link-local IPv6 addresses need a scope id on `addr`.
    pub async fn connect(
        addr: SocketAddr,
        identity: &QuicIdentity,
        options: QuicTunnelOptions,
    ) -> Result<Self, IdeviceError> {
        util::install_crypto_provider();
        let endpoint = client_endpoint(addr, identity, &options)?;
        log::debug!("connecting quic tunnel to {addr}");
        let connection = endpoint
            .connect(addr, &options.server_name)
            .map_err(|error| IdeviceError::Quic(error.to_string()))?
            .await
            .map_err(|error| IdeviceError::Quic(error.to_string()))?;
        log::debug!("quic connected, starting CDTunnel handshake");

        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| IdeviceError::Quic(error.to_string()))?;
        let (handshake, control) = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake(&connection, send, recv, options.requested_mtu),
        )
        .await
        .map_err(|_| IdeviceError::Quic("timed out waiting for CDTunnel response".to_string()))??;

        log::debug!(
            "quic tunnel ready, server {} rsd port {}",
            handshake.server_address,
            handshake.server_rsd_port
        );

        Ok(Self {
            endpoint,
            connection,
            control,
            handshake,
        })
    }

    /// CDTunnel parameters returned by the device.
    pub fn handshake(&self) -> &HandshakeResponse {
        &self.handshake
    }

    /// IPv6 address assigned to this side of the tunnel.
    pub fn client_address(&self) -> &str {
        &self.handshake.client_parameters.address
    }

    /// IPv6 address of the device inside the tunnel.
    pub fn server_address(&self) -> &str {
        &self.handshake.server_address
    }

    /// TCP port where Remote Service Discovery is listening inside the tunnel.
    pub fn server_rsd_port(&self) -> u16 {
        self.handshake.server_rsd_port
    }

    /// Sends one IPv6 packet.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<(), IdeviceError> {
        if packet.first().is_none_or(|byte| byte >> 4 != 6) {
            return Err(IdeviceError::Quic("tunnel packet is not IPv6".to_string()));
        }
        self.connection
            .send_datagram(bytes::Bytes::copy_from_slice(packet))
            .map_err(|error| IdeviceError::Quic(error.to_string()))
    }

    /// Receives the next IPv6 packet. Non-IPv6 datagrams are skipped.
    pub async fn recv_packet(&self) -> Result<Vec<u8>, IdeviceError> {
        loop {
            let datagram = self
                .connection
                .read_datagram()
                .await
                .map_err(|error| IdeviceError::Quic(error.to_string()))?;
            if datagram.first().is_some_and(|byte| byte >> 4 == 6) {
                return Ok(datagram.to_vec());
            }
            log::debug!("ignoring non-IPv6 quic datagram ({} bytes)", datagram.len());
        }
    }

    /// Converts the tunnel into a concatenated IPv6 byte stream.
    ///
    /// This consumes the tunnel, so [`Self::recv_packet`] cannot be used
    /// alongside the stream.
    pub fn into_packet_stream(self) -> QuicPacketStream {
        QuicPacketStream::from_parts(self.connection, self.endpoint, self.control)
    }

    /// Builds a userspace TCP adapter over this tunnel.
    ///
    /// Requires the `tunnel_tcp_stack` feature. Call [`crate::tcp::adapter::Adapter::to_async_handle`]
    /// on the result to connect to RSD and other tunnel services.
    #[cfg(feature = "tunnel_tcp_stack")]
    pub fn into_adapter(self) -> Result<crate::tcp::adapter::Adapter, IdeviceError> {
        let host = self.client_address().parse()?;
        let peer = self.server_address().parse()?;
        Ok(crate::tcp::adapter::Adapter::new(
            Box::new(self.into_packet_stream()),
            host,
            peer,
        ))
    }
}

#[derive(Serialize)]
struct HandshakeRequest<'a> {
    #[serde(rename = "type")]
    packet_type: &'a str,
    mtu: u32,
}

async fn handshake(
    connection: &quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mtu: u32,
) -> Result<(HandshakeResponse, ControlGuard), IdeviceError> {
    let probe = vec![b'x'; MTU_PROBE_LEN];
    connection
        .send_datagram(bytes::Bytes::from(probe))
        .map_err(|error| IdeviceError::Quic(error.to_string()))?;

    let request = HandshakeRequest {
        packet_type: "clientHandshakeRequest",
        mtu,
    };
    let packet = CDTunnelPacket::from_body(serde_json::to_vec(&request)?).serialize()?;
    send.write_all(&packet)
        .await
        .map_err(|error| IdeviceError::Quic(error.to_string()))?;
    send.flush()
        .await
        .map_err(|error| IdeviceError::Quic(error.to_string()))?;

    let response = read_cdtunnel(&mut recv).await?;
    let parsed = serde_json::from_slice::<HandshakeResponse>(response.body())?;
    let control = ControlGuard::new(tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match AsyncReadExt::read(&mut recv, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = send.finish();
    }));
    Ok((parsed, control))
}

async fn read_cdtunnel(recv: &mut quinn::RecvStream) -> Result<CDTunnelPacket, IdeviceError> {
    let mut header = [0u8; 10];
    recv.read_exact(&mut header)
        .await
        .map_err(|error| IdeviceError::Quic(error.to_string()))?;
    if &header[..8] != b"CDTunnel" {
        return Err(IdeviceError::CdtunnelPacketInvalidMagic);
    }
    let len = u16::from_be_bytes([header[8], header[9]]) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|error| IdeviceError::Quic(error.to_string()))?;
    let mut raw = Vec::with_capacity(header.len() + body.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&body);
    CDTunnelPacket::parse(&raw)
}

fn client_endpoint(
    peer: SocketAddr,
    identity: &QuicIdentity,
    options: &QuicTunnelOptions,
) -> Result<quinn::Endpoint, IdeviceError> {
    let provider = Arc::new(crypto_provider());
    let verifier = Arc::new(SkipServerVerification {
        provider: provider.clone(),
    });
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.rustls_certificate()], identity.rustls_key())?;
    rustls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|error| IdeviceError::Quic(format!("quic crypto config: {error}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config(options.idle_timeout)?));

    let bind = if peer.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| IdeviceError::Quic("tokio quic runtime is unavailable".to_string()))?;
    let mut endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
    endpoint.set_default_client_config(client);
    Ok(endpoint)
}

fn transport_config(idle_timeout: Duration) -> Result<quinn::TransportConfig, IdeviceError> {
    let mut transport = quinn::TransportConfig::default();
    let idle = idle_timeout
        .try_into()
        .map_err(|error| IdeviceError::Quic(format!("idle timeout: {error}")))?;
    transport.max_idle_timeout(Some(idle));
    if idle_timeout >= Duration::from_secs(2) {
        transport.keep_alive_interval(Some(idle_timeout / 2));
    }
    transport.datagram_receive_buffer_size(Some(MAX_DATAGRAM_SIZE));
    transport.datagram_send_buffer_size(MAX_DATAGRAM_SIZE);
    // iOS expects a path MTU near 1500 so a 1420-byte IP packet fits in one datagram.
    transport.initial_mtu(1452);
    Ok(transport)
}

#[derive(Debug)]
struct SkipServerVerification {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ipv6_packet(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        let len = (payload.len() as u16).to_be_bytes();
        packet[4] = len[0];
        packet[5] = len[1];
        packet[6] = 59;
        packet[7] = 64;
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn server_config(identity: &QuicIdentity) -> Result<quinn::ServerConfig, IdeviceError> {
        util::install_crypto_provider();
        let provider = Arc::new(crypto_provider());
        let mut rustls_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![identity.rustls_certificate()], identity.rustls_key())
            .map_err(|error| IdeviceError::Quic(error.to_string()))?;
        rustls_config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|error| IdeviceError::Quic(format!("quic server crypto: {error}")))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server.transport_config(Arc::new(transport_config(DEFAULT_IDLE_TIMEOUT)?));
        Ok(server)
    }

    async fn serve(endpoint: quinn::Endpoint) -> Result<(), String> {
        let incoming = endpoint.accept().await.ok_or("no incoming connection")?;
        let connection = incoming.await.map_err(|error| error.to_string())?;
        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|error| error.to_string())?;
        let request = read_cdtunnel(&mut recv)
            .await
            .map_err(|error| error.to_string())?;
        let request_json: serde_json::Value =
            serde_json::from_slice(request.body()).map_err(|error| error.to_string())?;
        assert_eq!(
            request_json["type"].as_str(),
            Some("clientHandshakeRequest")
        );

        let response = serde_json::json!({
            "clientParameters": {
                "mtu": 1420,
                "address": "fd00::1",
                "netmask": "ffff:ffff:ffff:ffff::"
            },
            "serverAddress": "fd00::2",
            "serverRSDPort": 58783,
            "type": "clientHandshakeResponse"
        });
        let packet = CDTunnelPacket::from_body(serde_json::to_vec(&response).unwrap())
            .serialize()
            .unwrap();
        send.write_all(&packet)
            .await
            .map_err(|error| error.to_string())?;

        loop {
            match connection.read_datagram().await {
                Ok(datagram) if datagram.first().is_some_and(|byte| byte >> 4 == 6) => {
                    connection
                        .send_datagram(datagram)
                        .map_err(|error| error.to_string())?;
                }
                Ok(_) => {}
                Err(_) => return Ok(()),
            }
        }
    }

    #[tokio::test]
    async fn handshake_echoes_ipv6_and_streams_packets() {
        let server_identity = QuicIdentity::generate().unwrap();
        let server = server_config(&server_identity).unwrap();
        let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            if let Err(error) = serve(endpoint).await {
                panic!("quic test server failed: {error}");
            }
        });

        let client_identity = QuicIdentity::generate().unwrap();
        let tunnel = tokio::time::timeout(
            Duration::from_secs(15),
            QuicTunnel::connect(addr, &client_identity, QuicTunnelOptions::default()),
        )
        .await
        .expect("connect timed out")
        .expect("connect");
        assert_eq!(tunnel.server_rsd_port(), 58783);
        assert_eq!(tunnel.client_address(), "fd00::1");
        assert_eq!(tunnel.server_address(), "fd00::2");

        let packet = ipv6_packet(b"ping");
        tunnel.send_packet(&packet).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), tunnel.recv_packet())
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(echoed, packet);

        let mut stream = tunnel.into_packet_stream();
        let second = ipv6_packet(b"pong-packet");
        stream.write_all(&second).await.unwrap();
        let mut got = vec![0u8; second.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut got))
            .await
            .expect("stream read timed out")
            .unwrap();
        assert_eq!(got, second);

        drop(stream);
        let _ = server_task.await;
    }

    #[cfg(feature = "tunnel_tcp_stack")]
    #[tokio::test]
    async fn adapter_uses_handshake_addresses() {
        let server_identity = QuicIdentity::generate().unwrap();
        let server = server_config(&server_identity).unwrap();
        let endpoint = quinn::Endpoint::server(server, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let _ = serve(endpoint).await;
        });

        let client_identity = QuicIdentity::generate().unwrap();
        let tunnel = tokio::time::timeout(
            Duration::from_secs(15),
            QuicTunnel::connect(addr, &client_identity, QuicTunnelOptions::default()),
        )
        .await
        .expect("connect timed out")
        .expect("connect");
        let adapter = tunnel.into_adapter().expect("adapter");
        drop(adapter);
        let _ = server_task.await;
    }
}
