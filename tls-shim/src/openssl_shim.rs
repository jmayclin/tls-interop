// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use common::{InteropTest, CLIENT_GREETING, LARGE_DATA_DOWNLOAD_GB};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use std::{error::Error, pin::Pin};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{openssl_shim::ffi::ForeignWrapperTrait, ServerTLS, ONE_GB, ONE_MB};

pub struct OpensslShim;

mod ffi {
    use libc::c_int;
    use openssl::{error::ErrorStack, ssl::SslRef};
    use openssl_sys::SSL;

    // https://github.com/openssl/openssl/blob/6594baf6457c64f6fce3ec60cb2617f75d98d159/include/openssl/ssl.h.in#L995-L1000
    const SSL_KEY_UPDATE_NOT_REQUESTED: c_int = 0;

    extern "C" {
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_key_update.html
        pub fn SSL_key_update(s: *const SSL, updatetype: c_int) -> c_int;
    }

    // https://github.com/sfackler/rust-openssl/blob/8e5d7bd402912ed3875dd8c4dcb510fc2f0c3686/openssl/src/lib.rs#L221C1-L227C2
    fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
        if r <= 0 {
            Err(ErrorStack::get())
        } else {
            Ok(r)
        }
    }

    // This is an extension trait allowing us to implement methods on the foreign
    // `SslRef`` type. This functionality should be moved upstream to the rust-openssl
    // crate, but I'm waiting to do that until the open PR for the `&mut` helper
    // is merged
    pub trait ForeignWrapperTrait {
        fn key_update(&self) -> Result<(), ErrorStack>;

        fn as_ptr(&self) -> *mut SSL;
    }

    impl ForeignWrapperTrait for SslRef {
        // this should take a &mut reference, but the tokio_openssl stream doesn't
        // allow for a mut ssl reference to be returned. A PR to add this
        // functionality has been opened upstream.
        // https://github.com/sfackler/rust-openssl/pull/2223
        fn key_update(&self) -> Result<(), ErrorStack> {
            unsafe {
                cvt(SSL_key_update(self.as_ptr(), SSL_KEY_UPDATE_NOT_REQUESTED))?;
            }
            Ok(())
        }

        fn as_ptr(&self) -> *mut SSL {
            self as *const openssl::ssl::SslRef as *mut openssl_sys::SSL
        }
    }
}

impl std::fmt::Display for OpensslShim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "s2n-tls")
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + core::fmt::Debug> ServerTLS<T> for OpensslShim {
    type Config = openssl::ssl::SslAcceptorBuilder;
    type Acceptor = openssl::ssl::SslAcceptor;
    type Stream = tokio_openssl::SslStream<T>;

    fn get_server_config(test: InteropTest) -> Result<Option<Self::Config>, Box<dyn Error>> {
        let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();
        acceptor.set_private_key_file(
            common::pem_file_path(common::PemType::ServerKey),
            SslFiletype::PEM,
        )?;
        acceptor.set_certificate_chain_file(common::pem_file_path(common::PemType::ServerChain))?;
        if test == InteropTest::MTLSRequestResponse {
            acceptor.set_ca_file(common::pem_file_path(common::PemType::CaCert))?;
            acceptor.set_verify(
                openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT
                    | openssl::ssl::SslVerifyMode::PEER,
            );
        }
        Ok(Some(acceptor))
    }

    fn acceptor(config: Self::Config) -> Self::Acceptor {
        config.build()
    }

    async fn accept(
        server: &Self::Acceptor,
        transport_stream: T,
    ) -> Result<Self::Stream, Box<dyn Error + Send + Sync>> {
        let ssl = openssl::ssl::Ssl::new(server.context()).unwrap();
        let mut ssl_stream = Self::Stream::new(ssl, transport_stream)?;
        Pin::new(&mut ssl_stream).accept().await.unwrap();
        Ok(ssl_stream)
    }

    async fn handle_large_data_download_with_frequent_key_updates(
        stream: &mut Self::Stream,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::info!("waiting for client greeting");
        let mut server_greeting_buffer = vec![0; CLIENT_GREETING.as_bytes().len()];
        stream.read_exact(&mut server_greeting_buffer).await?;
        assert_eq!(server_greeting_buffer, CLIENT_GREETING.as_bytes());

        let mut data_buffer = vec![0; ONE_MB];
        for i in 0..LARGE_DATA_DOWNLOAD_GB {
            // send a key update with each gigabyte
            stream.ssl().key_update()?;
            if i % 10 == 0 {
                tracing::info!("GB sent: {}", i);
            }
            data_buffer[0] = (i % u8::MAX as u64) as u8;
            for _ in 0..(ONE_GB / ONE_MB) {
                stream.write_all(&data_buffer).await?;
            }
        }

        Ok(())
    }
}
