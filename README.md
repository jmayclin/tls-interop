# Interop Tests
## Results 2024-05-21
```
handshake              , S2nTls    , S2nTls    , 🥳
handshake              , S2nTls    , Rustls    , 🥳
handshake              , S2nTls    , Java      , 🥳
handshake              , S2nTls    , Go        , 🥳
handshake              , OpenSSL   , S2nTls    , 🥳
handshake              , OpenSSL   , Rustls    , 🥳
handshake              , OpenSSL   , Java      , 🥳
handshake              , OpenSSL   , Go        , 🥳
greeting               , S2nTls    , S2nTls    , 🥳
greeting               , S2nTls    , Rustls    , 🥳
greeting               , S2nTls    , Java      , 🥳
greeting               , S2nTls    , Go        , 🥳
greeting               , OpenSSL   , S2nTls    , 🥳
greeting               , OpenSSL   , Rustls    , 🥳
greeting               , OpenSSL   , Java      , 🥳
greeting               , OpenSSL   , Go        , 🥳
large_data_download    , S2nTls    , S2nTls    , 🥳
large_data_download    , S2nTls    , Rustls    , 🥳
large_data_download    , S2nTls    , Java      , 💔
large_data_download    , S2nTls    , Go        , 🥳
large_data_download    , OpenSSL   , S2nTls    , 🥳
large_data_download    , OpenSSL   , Rustls    , 🥳
large_data_download    , OpenSSL   , Java      , 💔
large_data_download    , OpenSSL   , Go        , 🥳
large_data_download_with_frequent_key_updates, S2nTls    , S2nTls    , 🥳
large_data_download_with_frequent_key_updates, S2nTls    , Rustls    , 🥳
large_data_download_with_frequent_key_updates, S2nTls    , Java      , 🥳
large_data_download_with_frequent_key_updates, S2nTls    , Go        , 🥳
large_data_download_with_frequent_key_updates, OpenSSL   , S2nTls    , 🥳
large_data_download_with_frequent_key_updates, OpenSSL   , Rustls    , 🥳
large_data_download_with_frequent_key_updates, OpenSSL   , Java      , 🥳
large_data_download_with_frequent_key_updates, OpenSSL   , Go        , 🥳
mtls_request_response  , S2nTls    , S2nTls    , 🥳
mtls_request_response  , S2nTls    , Rustls    , 🥳
mtls_request_response  , S2nTls    , Java      , 🚧
mtls_request_response  , S2nTls    , Go        , 🥳
mtls_request_response  , OpenSSL   , S2nTls    , 🥳
mtls_request_response  , OpenSSL   , Rustls    , 🥳
mtls_request_response  , OpenSSL   , Java      , 🚧
mtls_request_response  , OpenSSL   , Go        , 🥳
```

🥳 -> success
💔 -> unimplemented
🚧 -> unimplemented

```
$ java --version
openjdk 21.0.2 2024-01-16 LTS
OpenJDK Runtime Environment Corretto-21.0.2.14.1 (build 21.0.2+14-LTS)
OpenJDK 64-Bit Server VM Corretto-21.0.2.14.1 (build 21.0.2+14-LTS, mixed mode, sharing)

$ go version
go version go1.22.2 linux/arm64
```

Java failures are expected, due to https://bugs.openjdk.org/browse/JDK-8329548

## Quickstart
```bash
# build the rust (binding) clients (s2n-tls, rustls, openssl)
cargo build --manifest-path  tls-shim/Cargo.toml --release
# build the java client
javac java/SSLSocketClient.java
# build the go client
cd go/
go build client.go
cd ..

cd common/
cargo run --bin runner
```
## Goal
The goal of the tests in this category is to test interoperability with other TLS implementations. 

## Structure
The interop tests are largely inspired by the work done with the [Quic Interop Runner](https://interop.seemann.io). Client and Server implementations are invoked with the name of the scenario under test, and then execute the scenario-specific logic. Clients and Servers communicate with each other in a "request/response" pattern. 

The only available client implementations are
- s2n-tls
- rustls
- java

And the only server implementation is
- s2n-tls

The interop runner defines a number of test cases. Binaries are invoked with the following arguments
```
client_binary $TEST_CASE $SERVER_PORT
```
```
server_binary $TEST_CASE $SERVER_PORT
```

## Tests
All tests currently use TLS 1.3. Acceptable cipher suites/groups are not specified

- Handshake (`handshake`)
    1. handshake
    2. client initiates graceful TLS closure
- Greeting (`greeting`)
    1. handshake
    2. client sends `i am the client. nice to meet you server.`
    3. server responds `i am the server. a pleasure to make your acquaintance.`
    4. client initiates graceful TLS closure
- Large Data Download (`large_data_download`): 
    1. handshake
    2. client sends `i am the client. nice to meet you server.`
    3. server responds with 256 Gb of data. This number is chosen to be higher than the default key update limits that most implementations have set
        - The first byte of each Mb (1,000,000 bytes) is equal to the "Gb's sent". So the first 1,000 Mb have `payload[0] = 0`. The next 1,000 Mb have `payload[0] = 1`, and so on.
    4. client initiates graceful TLS closure
- Large Data Download with Frequent Key Updates (`large_data_download_with_frequent_key_updates`):
    1. handshake
    2. client sends `i am the client. nice to meet you server.`
    3. server responds with 256 Gb of data, identical to the data sent in the `Large Data Download` trial.
    4. server updates it's send key every Gb. This is not a precisely monitored number, but servers should send ~256 Key Updates over the course of this scenario
    5. client initiates graceful TLS closure

### Test Context

The "Large Data Download" cases are motivated by JDK behavior: https://bugs.openjdk.org/browse/JDK-8329548. As of 2024-04-16 the JDK will send a KeyUpdate message for each TLS record that it receives past it's CipherLimit (137 Gb). Typical server implementations won't stop to read those messages until they are finished sending data. This results in a huge number of KeyUpdates exhausting the TCP flow control window, deadlocking the connection and causing the Large Data Download tests to time out and fail. If the server sends a key update before the JDK requests them this behavior can be avoided, so the `Large Data Download With Frequent Key Updates` scenario is expected to pass.

### Future Tests

- Server Initiated Close
- Half Close
- Resumption
    - example incompatibility: https://github.com/aws/s2n-tls/issues/4124
- Early Data
- OOB PSK
- Client Hello Retry
    - example incompatibility: https://github.com/rustls/rustls/issues/1373
- Small TCP Packet

## Certificates

Test certificates are available in [interop/certificates](certificates). Clients should trust `ca-certificate.pem`, and servers should send the full `server-chain.pem`.
