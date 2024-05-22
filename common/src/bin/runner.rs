// PORT_START: u16 = 9_000;
// PORT_END: u16 = 9_100;

use common::{InteropTest, UNIMPLEMENTED_RETURN_VAL};
use std::collections::BTreeMap;
use std::time::Instant;
use std::{process::Stdio, sync::Arc, thread, time::Duration};
use tokio::{
    process::Command,
    sync::{mpsc::unbounded_channel, Semaphore},
    time::{sleep, timeout},
};
use tracing::Level;

/// Tests communicate over the localhost TCP start. PORT_RANGE_START indicates the
/// first port that will be used, with the nth scenario using PORT_RANGE_START + n
const PORT_RANGE_START: u16 = 9_001;
/// If a test does not successfully complete within this duration, then it is
/// considered to have failed
/// 
/// Long pole as of 2024-04-19 was Rustls/OpenSSL large data download test
const TEST_TIMEOUT: Duration = Duration::from_secs(7 * 60);

const ENABLED_TESTS: [InteropTest; 5] = [
    InteropTest::Handshake,
    InteropTest::Greeting,
    InteropTest::MTLSRequestResponse,
    InteropTest::LargeDataDownload,
    InteropTest::LargeDataDownloadWithFrequentKeyUpdates,
    //InteropTest::SessionResumption,
];

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum Client {
    S2nTls,
    Rustls,
    Java,
    Go,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum Server {
    S2nTls,
    OpenSSL,
}

impl Client {
    fn executable_path(&self) -> &'static str {
        match self {
            Client::S2nTls => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim/target/release/s2n_tls_client"
            ),
            Client::Rustls => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim/target/release/rustls_client"
            ),
            Client::Java => "java",
            Client::Go => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/go/client"
            ),
        }
    }

    // lifetimes are used to indicate that the returned `&mut Command` has the same
    // lifetime as the input `&mut Command`
    fn configure<'a, 'b>(&'a self, command: &'b mut Command) -> &'b mut Command {
        match self {
            Client::Java => command
                // configure the class path (-cp)
                .arg("-cp")
                // to point to the folder that contains the SSLSocketClient
                .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/..", "/java"))
                // and use the SSLSocketClient as the entry point
                .arg("SSLSocketClient"),
            _ => command,
        }
    }
}

impl Server {
    fn executable_path(&self) -> &'static str {
        match self {
            Server::S2nTls => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim/target/release/s2n_tls_server"
            ),
            Server::OpenSSL => concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/..",
                "/tls-shim/target/release/openssl_server"
            ),
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum TestResult {
    Success,
    Failure,
    Unimplemented,
}

#[derive(Debug)]
struct TestScenario {
    client: Client,
    server: Server,
    test_case: InteropTest,
}

impl TestScenario {
    async fn execute(&mut self, port: u16) -> TestResult {
        let start_time = Instant::now();
        let test_case_name = format!("{}", self.test_case);

        let server_log = format!(
            "interop_logs/{}_{:?}_{:?}_server.log",
            self.test_case, self.server, self.client
        );
        let client_log = format!(
            "interop_logs/{}_{:?}_{:?}_client.log",
            self.test_case, self.server, self.client
        );
        let mut server_log = tokio::fs::File::create(server_log).await.unwrap();
        let mut client_log = tokio::fs::File::create(client_log).await.unwrap();

        // fn executable_path(&self, test_case) -> 
        let mut server = tokio::process::Command::new(self.server.executable_path())
            .args([&test_case_name, &port.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut server_stdout = server.stdout.take().unwrap();

        // let the server start up and start listening before starting the client
        sleep(Duration::from_secs(1)).await;

        let mut client_command = tokio::process::Command::new(self.client.executable_path());
        let mut client = self
            .client
            .configure(&mut client_command)
            .args([&test_case_name, &port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut client_stdout = client.stdout.take().unwrap();

        // wrap everything in a timeout since the "try_join" macro needs everything
        // to have the same error type
        let res = tokio::try_join!(
            timeout(TEST_TIMEOUT, client.wait()),
            timeout(TEST_TIMEOUT, server.wait()),
            // we use tokio::io::copy to copy the println logging of the processes
            // to a log file.
            timeout(
                TEST_TIMEOUT,
                tokio::io::copy(&mut client_stdout, &mut client_log)
            ),
            timeout(
                TEST_TIMEOUT,
                tokio::io::copy(&mut server_stdout, &mut server_log)
            ),
        );

        tracing::debug!(
            "{:?} finished in {} seconds",
            self,
            start_time.elapsed().as_secs()
        );

        let (c_status, s_status) = match res {
            Ok((Ok(s), Ok(c), Ok(_), Ok(_))) => (c, s),
            Err(_) => {
                // a timeout indicates an "abnormal" exit which must be manually
                // cleaned up
                tracing::error!("{:?} timed out", self);
                server.kill().await.unwrap();
                client.kill().await.unwrap();
                return TestResult::Failure;
            }
            _ => return TestResult::Failure,
        };
        let c_status = c_status.code().unwrap();
        let s_status = s_status.code().unwrap();

        if c_status == UNIMPLEMENTED_RETURN_VAL || s_status == UNIMPLEMENTED_RETURN_VAL {
            TestResult::Unimplemented
        } else if c_status == 0 && s_status == 0 {
            TestResult::Success
        } else {
            TestResult::Failure
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::fmt()
        .with_max_level(Level::DEBUG)
        .with_ansi(false)
        .init();

    tokio::fs::create_dir_all("interop_logs").await.unwrap();

    let clients = vec![Client::S2nTls, Client::Rustls, Client::Java, Client::Go];
    //let clients = vec![Client::Java];
    let servers = vec![Server::S2nTls, Server::OpenSSL];

    let mut scenarios = Vec::new();

    for t in ENABLED_TESTS {
        for s in servers.iter() {
            for c in clients.iter() {
                scenarios.push(TestScenario {
                    client: *c,
                    server: *s,
                    test_case: t,
                })
            }
        }
    }

    let (results_tx, mut results_rx) = unbounded_channel();
    let mut results = Vec::new();
    // The large tests are capable of saturating 2 cores (1 for the client and 1
    // for the server) so we limit the number of concurrent tests to NUM_CORES / 2
    let concurrent_tests = thread::available_parallelism().unwrap().get() / 2;
    tracing::debug!("Setting concurrency to {concurrent_tests}");
    let concurrent_tests = Arc::new(Semaphore::new(concurrent_tests));
    for (i, mut scenario) in scenarios.into_iter().enumerate() {
        let results_tx_handle = results_tx.clone();
        let test_limiter_handle = Arc::clone(&concurrent_tests);
        tokio::spawn(async move {
            let ticket = test_limiter_handle.acquire().await.unwrap();
            let result = scenario.execute(PORT_RANGE_START + (i as u16)).await;
            drop(ticket);
            // something has gone drastically wrong if this panics, so use unwrap
            results_tx_handle.send((scenario, result)).unwrap();
        });
    }
    // we manually drop results_tx, because the channel will never return "None"
    // on a read if there is a sender still open
    drop(results_tx);

    while let Some((scenario, result)) = results_rx.recv().await {
        tracing::info!("{:?} finished with {:?}", scenario, result);
        let result = match result {
            TestResult::Success => "🥳",
            TestResult::Failure => "💔",
            TestResult::Unimplemented => "🚧",
        }.to_owned();

        results.push((scenario.test_case, scenario.server, scenario.client, result));
        results.sort();
        print_results_table(&results);
    }
}

fn print_results_table(results: &Vec<(InteropTest, Server, Client, String)>) {
    for (test, server, client, result) in results {
        println!("{:23}, {:10}, {:10}, {}", test.to_string(), format!("{:?}",server), format!("{:?}",client), result);
    }
}
