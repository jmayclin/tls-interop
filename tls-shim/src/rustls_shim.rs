// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    io::BufReader,
    sync::Arc,
};

use common::InteropTest;
use rustls_pemfile::pkcs8_private_keys;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{self, PrivateKeyDer},
    },
    TlsConnector,
};

use crate::ClientTLS;

pub struct RustlsShim;

impl Display for RustlsShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rustls")
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> ClientTLS<T> for RustlsShim {
    type Config = Arc<tokio_rustls::rustls::ClientConfig>;
    type Connector = tokio_rustls::TlsConnector;
    type Stream = tokio_rustls::client::TlsStream<T>;

    fn get_client_config(
        test: common::InteropTest,
    ) -> Result<Option<Self::Config>, Box<dyn std::error::Error>> {
        let mut root_store = rustls::RootCertStore::empty();

        let ca_pem = std::fs::read(common::pem_file_path(common::PemType::CaCert))?;
        let mut ca_reader = BufReader::new(ca_pem.as_slice());
        let root_cert = rustls_pemfile::certs(&mut ca_reader)
            .next()
            .unwrap()
            .unwrap();
        root_store.add(root_cert).unwrap();

        let config = match test {
            InteropTest::Greeting
            | InteropTest::Handshake
            | InteropTest::LargeDataDownload
            | InteropTest::LargeDataDownloadWithFrequentKeyUpdates => {
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            }
            InteropTest::MTLSRequestResponse => {
                let mut chain_reader = BufReader::new(std::fs::File::open(common::pem_file_path(
                    common::PemType::ClientChain,
                ))?);
                let client_chain = rustls_pemfile::certs(&mut chain_reader)
                    .map(|maybe_cert| maybe_cert.unwrap())
                    .collect();

                let mut key_reader = BufReader::new(std::fs::File::open(common::pem_file_path(
                    common::PemType::ClientKey,
                ))?);
                let client_key = pkcs8_private_keys(&mut key_reader).next().unwrap()?;
                let client_key = PrivateKeyDer::Pkcs8(client_key);
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(client_chain, client_key)?
            }
            _ => return Ok(None),
        };

        Ok(Some(Arc::new(config)))
    }

    fn connector(config: Self::Config) -> Self::Connector {
        TlsConnector::from(config)
    }

    async fn connect(
        client: &Self::Connector,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn std::error::Error + Send + Sync>> {
        let domain = "localhost";
        let server_name = pki_types::ServerName::try_from(domain)?;
        Ok(client.connect(server_name, transport_stream).await?)
    }
}
