// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB};
use s2n_tls::{callbacks::{ConnectionFuture, SessionTicketCallback}, config::{Config, ConnectionInitializer}, security::DEFAULT_TLS13};
use tracing::{debug, info};

use std::{alloc::System, cell::RefCell, error::Error, pin::Pin, sync::{Arc, Mutex}, time::SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{ClientTLS, ServerTLS};

const STEK_NAME: &[u8; 9] = b"test_stek";
const STEK_VALUE: [u8; 19] = [3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,4,6];

pub struct S2NShim;

impl std::fmt::Display for S2NShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n-tls")
    }
}

#[derive(Default, Clone)]
struct SessionTicketStorage {
    ticket:Arc<Mutex<Option<Vec<u8>>>>,
}

impl SessionTicketCallback for SessionTicketStorage {
    fn on_session_ticket(&self, _connection: &mut s2n_tls::connection::Connection, session_ticket: &s2n_tls::callbacks::SessionTicket) {
        debug!("received a session ticket");
        let mut ticket = vec![0; session_ticket.len().unwrap()];
        session_ticket.data(&mut ticket).unwrap();
        self.ticket.lock().unwrap().replace(ticket);
    }
}

impl ConnectionInitializer for SessionTicketStorage {
    fn initialize_connection(
        &self,
        connection: &mut s2n_tls::connection::Connection,
    ) -> Result<Option<Pin<Box<dyn ConnectionFuture>>>, s2n_tls::error::Error> {
        let ticket = self.ticket.lock().unwrap();
        if ticket.is_some() {
            tracing::info!("setting the session ticket");
            connection.set_session_ticket(ticket.as_ref().unwrap())?;
        }
        Ok(None)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ClientTLS<T> for S2NShim {
    type Config = s2n_tls::config::Config;
    type Connector = s2n_tls_tokio::TlsConnector;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_client_config(
        test: common::InteropTest,
    ) -> Result<Option<Self::Config>, Box<dyn Error>> {
        let ca_pem = std::fs::read(common::pem_file_path(common::PemType::CaCert))?;
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.trust_pem(&ca_pem)?;

        // additional configuration
        match test {
            InteropTest::MTLSRequestResponse => {
                config.load_pem(
                    &std::fs::read(common::pem_file_path(common::PemType::ClientChain))?,
                    &std::fs::read(common::pem_file_path(common::PemType::ClientKey))?,
                )?;
            },
            InteropTest::SessionResumption => {
                let storage = SessionTicketStorage::default();
                config.set_session_ticket_callback(storage.clone())?;
                config.set_connection_initializer(storage.clone())?;
            }
            _ => {/* no additional configuration required */},
        }
        Ok(Some(config.build()?))
    }

    fn connector(config: Self::Config) -> Self::Connector {
        s2n_tls_tokio::TlsConnector::new(config)
    }

    async fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn Error + Send + Sync>> {
        Ok(client.connect("localhost", transport_stream).await?)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> ServerTLS<T> for S2NShim {
    type Config = s2n_tls::config::Config;
    type Acceptor = s2n_tls_tokio::TlsAcceptor;
    type Stream = s2n_tls_tokio::TlsStream<T>;

    fn get_server_config(
        test: InteropTest,
    ) -> Result<Option<s2n_tls::config::Config>, Box<dyn Error>> {
        info!("getting the server config for {}", test);
        let cert_pem = std::fs::read(common::pem_file_path(common::PemType::ServerChain))?;
        let key_pem = std::fs::read(common::pem_file_path(common::PemType::ServerKey))?;
        let mut config = Config::builder();
        config.set_security_policy(&DEFAULT_TLS13)?;
        config.load_pem(&cert_pem, &key_pem)?;
        match test{
            InteropTest::MTLSRequestResponse => {
                config.trust_pem(&std::fs::read(common::pem_file_path(
                    common::PemType::CaCert,
                ))?)?;
            },
            InteropTest::SessionResumption => {
                config
                    .enable_session_tickets(true)?
                    .add_session_ticket_key(STEK_NAME, &STEK_VALUE, SystemTime::UNIX_EPOCH)?;
            }
            _ => {/* no additional configuration required */}

        }
        Ok(Some(config.build()?))
    }

    fn acceptor(config: Self::Config) -> Self::Acceptor {
        s2n_tls_tokio::TlsAcceptor::new(config)
    }

    async fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn Error + Send + Sync>> {
        Ok(server.accept(transport_stream).await?)
    }

    async fn handle_large_data_download_with_frequent_key_updates(
        stream: &mut Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::info!("waiting for client greeting");
        let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
        stream.read_exact(&mut server_greeting_buffer).await?;
        assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

        let mut data_buffer = vec![0; 1_000_000];
        for i in 0..LARGE_DATA_DOWNLOAD_GB {
            stream
                .as_mut()
                .request_key_update(s2n_tls::enums::PeerKeyUpdate::KeyUpdateNotRequested)?;
            if i % 10 == 0 {
                tracing::info!(
                    "GB sent: {}, key updates: {:?}",
                    i,
                    stream.as_ref().key_update_counts()?
                );
            }
            data_buffer[0] = (i % u8::MAX as u64) as u8;
            for j in 0..1_000 {
                tracing::trace!("{}-{}", i, j);
                stream.write_all(&data_buffer).await?;
            }
        }

        let updates = stream.as_ref().key_update_counts()?;
        assert!(updates.send_key_updates > 0);
        Ok(())
    }

    fn validate_resumption(stream: &Self::Stream) -> bool {
        !stream.as_ref()
        .handshake_type()
        .unwrap()
        .contains("FULL_HANDSHAKE")
    }
}
