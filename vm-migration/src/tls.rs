// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use thiserror::Error;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::io::{ReadVolatile, WriteVolatile};
use vm_memory::{VolatileMemoryError, VolatileSlice};

use crate::MigratableError;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error(
        "The provided input could not be parsed because it is not a syntactically-valid DNS Name."
    )]
    InvalidDnsName(#[source] InvalidDnsNameError),

    #[error("Rustls protocol error")]
    RustlsError(#[from] rustls::Error),

    #[error("Rustls protocol IO error")]
    RustlsIoError(#[from] std::io::Error),

    #[error("Error during TLS handshake: {0}")]
    HandshakeError(String),

    #[error("Error handling PEM file")]
    RustlsPemError(#[from] rustls::pki_types::pem::Error),
}

// This TlsStream will be later encapsulated in a SocketStream. Thus it has to
// implement the same traits. It is important that we never directly read from
// or write to the TcpStream encapsulated in StreamOwned.
#[derive(Debug)]
pub enum TlsStream {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

// The TLS-Stream objects cannot read or write volatile, thus we need a buffer
// between the VolatileSlice and the TLS stream (see ReadVolatile and
// WriteVolatile implementations below). Allocating this buffer in these
// function calls would make it very slow, thus we tie the buffer to the stream
// with this wrapper.
pub struct TlsStreamWrapper {
    stream: TlsStream,
    // Used only in ReadVolatile and WriteVolatile
    buf: Vec<u8>,
}

static MAX_CHUNK: usize = 1024 * 64;

impl TlsStreamWrapper {
    pub fn new(stream: TlsStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TlsStream::Client(s) => s.read(buf),
            TlsStream::Server(s) => s.read(buf),
        }
    }
}

impl Read for TlsStreamWrapper {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(&mut self.stream, buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TlsStream::Client(s) => s.write(buf),
            TlsStream::Server(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            TlsStream::Client(s) => s.flush(),
            TlsStream::Server(s) => s.flush(),
        }
    }
}

impl Write for TlsStreamWrapper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(&mut self.stream, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Write::flush(&mut self.stream)
    }
}

// Reading from or writing to these FDs would break the connection, because
// those reads or writes wouldn't go through rustls. But the FD is used to wait
// until it becomes readable.
impl AsFd for TlsStreamWrapper {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.stream {
            TlsStream::Client(s) => s.get_ref().as_fd(),
            TlsStream::Server(s) => s.get_ref().as_fd(),
        }
    }
}

impl ReadVolatile for TlsStreamWrapper {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        vs: &mut VolatileSlice<B>,
    ) -> std::result::Result<usize, VolatileMemoryError> {
        let len = vs.len().min(MAX_CHUNK);

        if len == 0 {
            return Ok(0);
        }

        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }

        let buf = &mut self.buf[..len];
        let n =
            Read::read(&mut self.stream, &mut buf[..len]).map_err(VolatileMemoryError::IOError)?;

        if n == 0 {
            return Ok(0);
        }

        vs.copy_from(&buf[..n]);
        self.buf.clear();

        Ok(n)
    }
}

impl WriteVolatile for TlsStreamWrapper {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        vs: &VolatileSlice<B>,
    ) -> std::result::Result<usize, VolatileMemoryError> {
        let len = vs.len().min(MAX_CHUNK);
        if len == 0 {
            return Ok(0);
        }

        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }

        let buf = &mut self.buf[..len];
        let n = vs.copy_to(&mut buf[..len]);

        if n == 0 {
            return Ok(0);
        }

        let n = Write::write(&mut self.stream, &buf[..n]).map_err(VolatileMemoryError::IOError)?;
        self.buf.clear();

        Ok(n)
    }
}

// A small wrapper to be put into ReceiveListener::Tls. It carries the
// TLS-Config and creates a TlsStream after the TcpConnection accepted a
// connection.
#[derive(Debug, Clone)]
pub struct TlsConnectionWrapper {
    config: Arc<ServerConfig>,
}

impl TlsConnectionWrapper {
    pub fn new(cert_dir: &Path) -> Result<Self, MigratableError> {
        let certs = CertificateDer::pem_file_iter(cert_dir.join("server-cert.pem"))
            .map_err(TlsError::RustlsPemError)?
            .map(|cert| cert.map_err(TlsError::RustlsPemError))
            .collect::<Result<Vec<CertificateDer<'_>>, TlsError>>()?;
        let key = PrivateKeyDer::from_pem_file(cert_dir.join("server-key.pem"))
            .map_err(TlsError::RustlsPemError)?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(TlsError::RustlsError)?;
        let config = Arc::new(config);
        Ok(Self { config })
    }

    pub fn wrap(
        &self,
        socket: TcpStream,
    ) -> std::result::Result<TlsStreamWrapper, MigratableError> {
        let conn = ServerConnection::new(self.config.clone()).map_err(TlsError::RustlsError)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)?;
            if rd == 0 && wr == 0 {
                Err(TlsError::HandshakeError(
                    "EOF during TLS handshake".to_string(),
                ))?;
            }
        }

        Ok(TlsStreamWrapper::new(TlsStream::Server(tls)))
    }
}

pub fn client_stream(
    socket: TcpStream,
    cert_dir: &Path,
    hostname: &str,
) -> std::result::Result<StreamOwned<ClientConnection, TcpStream>, MigratableError> {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(cert_dir.join("ca-cert.pem"))
            .map_err(TlsError::RustlsPemError)?
            .map(|cert| cert.map_err(TlsError::RustlsPemError))
            .collect::<Result<Vec<CertificateDer<'_>>, TlsError>>()?,
    );
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);
    let server_name =
        ServerName::try_from(hostname.to_string()).map_err(TlsError::InvalidDnsName)?;
    let conn = ClientConnection::new(config.clone(), server_name.clone())
        .map_err(TlsError::RustlsError)?;

    let mut tls = StreamOwned::new(conn, socket);
    while tls.conn.is_handshaking() {
        let (rd, wr) = tls
            .conn
            .complete_io(&mut tls.sock)
            .map_err(TlsError::RustlsIoError)?;
        if rd == 0 && wr == 0 {
            Err(TlsError::HandshakeError(
                "EOF during TLS handshake".to_string(),
            ))?;
        }
    }

    Ok(tls)
}
