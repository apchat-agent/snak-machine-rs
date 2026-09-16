//! Incremental TLS with explicit provider, bounded I/O and fixed handshake deadlines.
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use std::{
    io::{self, Read, Write},
    sync::Arc,
};
#[derive(Debug)]
struct Opportunistic {
    provider: rustls::crypto::CryptoProvider,
}
impl ServerCertVerifier for Opportunistic {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
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
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
/// RFC 7858 opportunistic privacy: no PKI identity claim; TLS key-possession checks remain.
pub fn opportunistic_client() -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = super::crypto_provider();
    let verifier = Arc::new(Opportunistic {
        provider: provider.clone(),
    });
    let mut c = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"dot".to_vec()];
    Ok(c)
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Open,
    Closing,
    Failed,
}
pub struct Session {
    connection: rustls::Connection,
    started: u64,
    last: u64,
    phase: Phase,
    peer_closed: bool,
    plaintext_pending: usize,
    handshake_bytes: usize,
}
impl Session {
    pub fn new(config: Arc<rustls::ServerConfig>, now: u64) -> io::Result<Self> {
        Self::with_connection(
            rustls::Connection::Server(
                rustls::ServerConnection::new(config).map_err(|_| invalid())?,
            ),
            now,
        )
    }
    pub fn client(
        config: Arc<rustls::ClientConfig>,
        name: ServerName<'static>,
        now: u64,
    ) -> io::Result<Self> {
        Self::with_connection(
            rustls::Connection::Client(
                rustls::ClientConnection::new(config, name).map_err(|_| invalid())?,
            ),
            now,
        )
    }
    fn with_connection(mut connection: rustls::Connection, now: u64) -> io::Result<Self> {
        connection.set_buffer_limit(Some(8192));
        Ok(Self {
            connection,
            started: now,
            last: now,
            phase: Phase::Open,
            peer_closed: false,
            plaintext_pending: 0,
            handshake_bytes: 0,
        })
    }
    pub fn readable(&self) -> bool {
        self.plaintext_pending > 0
    }
    pub fn handshaking(&self) -> bool {
        self.connection.is_handshaking()
    }
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }
    pub fn wants_write(&self) -> bool {
        self.connection.wants_write()
    }
    pub fn deadline(&self) -> u64 {
        if self.handshaking() {
            self.started.saturating_add(10000)
        } else {
            self.last.saturating_add(120000)
        }
    }
    pub fn tick(&mut self, now: u64) -> io::Result<()> {
        if self.phase == Phase::Failed || now >= self.deadline() {
            self.phase = Phase::Failed;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS connection failed or expired",
            ));
        }
        Ok(())
    }
    pub fn input(&mut self, b: &[u8], now: u64) -> io::Result<usize> {
        self.tick(now)?;
        if b.is_empty() || self.plaintext_pending > 0 {
            return Ok(0);
        }
        let result = (|| {
            let limit = b.len().min(4096);
            if self.handshaking() && self.handshake_bytes + limit > 16384 {
                return Err(invalid());
            }
            let n = self.connection.read_tls(&mut &b[..limit])?;
            if self.handshaking() {
                self.handshake_bytes += n;
            }
            let state = self
                .connection
                .process_new_packets()
                .map_err(|_| invalid())?;
            self.peer_closed = state.peer_has_closed();
            self.plaintext_pending = state.plaintext_bytes_to_read();
            if n > 0 {
                self.last = now;
            }
            Ok(n)
        })();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
    pub fn plaintext(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        if self.phase == Phase::Failed {
            return Err(invalid());
        }
        let mut b = vec![0; limit.min(16384)];
        match self.connection.reader().read(&mut b) {
            Ok(n) => {
                self.plaintext_pending = self.plaintext_pending.saturating_sub(n);
                b.truncate(n);
                Ok(b)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(vec![]),
            Err(_) => {
                self.phase = Phase::Failed;
                Err(invalid())
            }
        }
    }
    pub fn send_plaintext(&mut self, b: &[u8], now: u64) -> io::Result<usize> {
        self.tick(now)?;
        if self.phase != Phase::Open || self.handshaking() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TLS is not ready for plaintext",
            ));
        }
        let n = self.connection.writer().write(b)?;
        if n > 0 {
            self.last = now;
        }
        Ok(n)
    }
    pub fn write_tls(&mut self, out: &mut impl Write, now: u64) -> io::Result<usize> {
        self.tick(now)?;
        let n = self.connection.write_tls(out)?;
        if n > 0 {
            self.last = now;
        }
        Ok(n)
    }
    pub fn take_tls(&mut self, limit: usize, now: u64) -> io::Result<Vec<u8>> {
        let mut out = Limited {
            bytes: vec![],
            remaining: limit.min(8192),
        };
        self.write_tls(&mut out, now)?;
        Ok(out.bytes)
    }
    pub fn close_notify(&mut self) {
        if self.phase == Phase::Open {
            self.connection.send_close_notify();
            self.phase = Phase::Closing;
        }
    }
    pub fn end_input(&mut self) -> io::Result<()> {
        self.connection.read_tls(&mut &[][..])?;
        if self.peer_closed {
            Ok(())
        } else {
            self.phase = Phase::Failed;
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS closed without close-notify",
            ))
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "TLS protocol error")
}
struct Limited {
    bytes: Vec<u8>,
    remaining: usize,
}
impl Write for Limited {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = b.len().min(self.remaining);
        self.bytes.extend(&b[..n]);
        self.remaining -= n;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
