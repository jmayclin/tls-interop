use common::InteropTest;
use rand::SeedableRng;
use tracing::Level;

use std::net::{Ipv4Addr, SocketAddrV4};
use tls_shim_interop::{
    openssl_shim::OpensslShim, rustls_shim::RustlsShim, s2n_tls_shim::S2NShim, ClientTLS, ServerTLS,
};

use turmoil::Sim;

// turmoil's send function seems to be quadratic somewhere. Sending 1 Gb takes approximately 229 seconds
// so don't enable the large data tests.
const TEST_CASES: [InteropTest; 1] = [
    //InteropTest::Greeting,
    //InteropTest::Handshake,
    //InteropTest::MTLSRequestResponse,
    InteropTest::SessionResumption,
    // InteropTest::LargeDataDownload,
    // InteropTest::LargeDataDownloadWithFrequentKeyUpdates,
];

const PORT: u16 = 1738;

// async fn server_handle_connection<T>(test: InteropTest, acceptor: T::Config) -> Result<(), Box<dyn std::error::Error>> 
// where
//     T: ServerTLS<turmoil::net::TcpStream>
// {
//     let server = T::acceptor(config);

//     let listener =
//         turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

//     let (stream, _peer_addr) = listener.accept().await?;

//     let server_clone = server.clone();
//     let tls = T::accept(&server_clone, stream).await.unwrap();
//     T::handle_server_connection(test, tls).await.unwrap();
//     Ok(())
// }

async fn server_loop<T>(test: InteropTest) -> Result<(), Box<dyn std::error::Error>>
where
    T: ServerTLS<turmoil::net::TcpStream>,
{
    let config = T::get_server_config(test)?.unwrap();
    let listener = turmoil::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT)).await?;

    let server = T::acceptor(config);
    
    if test == InteropTest::SessionResumption {
        let (stream, _peer_addr) = listener.accept().await?;
        let server_clone = server.clone();
        let tls = T::accept(&server_clone, stream).await.unwrap();
        T::handle_server_connection(InteropTest::Greeting, tls).await.unwrap();
    }
    let (stream, _peer_addr) = listener.accept().await?;
    let server_clone = server.clone();
    let tls = T::accept(&server_clone, stream).await.unwrap();
    T::handle_server_connection(test, tls).await.unwrap();
    Ok(())
}

async fn client_loop<T>(
    test: InteropTest,
    server_domain: String,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: ClientTLS<turmoil::net::TcpStream>,
{
    let config = T::get_client_config(test)?.unwrap();
    let client = T::connector(config);

    if test == InteropTest::SessionResumption {
        let transport_stream = turmoil::net::TcpStream::connect((server_domain.as_str(), PORT)).await?;
        let tls = T::connect(&client, transport_stream).await.unwrap();
        // I keep getting panics here
        // called `Result::unwrap()` on an `Err` value: Custom { kind: ConnectionReset, error: "Connection reset" }
        // note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
        T::handle_client_connection(test, tls).await.unwrap();
    }
    let transport_stream = turmoil::net::TcpStream::connect((server_domain, PORT)).await?;
    let tls = T::connect(&client, transport_stream).await.unwrap();
    T::handle_client_connection(test, tls).await.unwrap();
    Ok(())
}

fn setup_scenario<S, C>(sim: &mut Sim, test: InteropTest)
where
    S: ServerTLS<turmoil::net::TcpStream> + 'static,
    C: ClientTLS<turmoil::net::TcpStream> + 'static,
{
    // let server_name = format!(
    //     "{}-{}-{}-server",
    //     std::any::type_name::<S>(),
    //     std::any::type_name::<C>(),
    //     test
    // );
    // let client_name = format!(
    //     "{}-{}-{}-client",
    //     std::any::type_name::<S>(),
    //     std::any::type_name::<C>(),
    //     test
    // );
    let server_name = format!(
        "{}-server",
        test
    );
    let client_name = format!(
        "{}-client",
        test
    );
    sim.host(server_name.as_str(), move || server_loop::<S>(test));
    sim.client(client_name, client_loop::<C>(test, server_name));
}

#[test]
fn turmoil_interop() -> turmoil::Result {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::INFO)
        .init();
    for i in 0..100 {
        let rand = Box::new(rand::rngs::SmallRng::seed_from_u64(7));
        let mut sim = turmoil::Builder::new().build_with_rng(rand);
    
        for t in TEST_CASES {
            setup_scenario::<S2NShim, RustlsShim>(&mut sim, t);
            //setup_scenario::<S2NShim, S2NShim>(&mut sim, t);
            //setup_scenario::<OpensslShim, RustlsShim>(&mut sim, t);
            //setup_scenario::<OpensslShim, S2NShim>(&mut sim, t);
        }
    
        sim.run().unwrap();
    }
    Ok(())
}
