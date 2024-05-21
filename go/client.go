package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

const (
	LargeDataDownloadGB = 256
	ClientGreeting      = "i am the client. nice to meet you server."
	ServerGreeting      = "i am the server. a pleasure to make your acquaintance."
	Host                = "localhost"
)

func main() {
	// Parse the test arguments
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <test_case> <port>")
		return
	}
	testCase := os.Args[1]
	port := os.Args[2]

	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair("../certificates/client-cert.pem", "../certificates/client-key.pem")
	if err != nil {
		fmt.Println("Error loading client certificate:", err)
		return
	}

	// Load CA certificate
	certificatePath := "../certificates/ca-cert.pem"
	cert, err := os.ReadFile(certificatePath)
	if err != nil {
		fmt.Println("Error loading CA certificate:", err)
		return
	}

	// Create certificate pool and add CA certificate
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(cert) {
		fmt.Println("Failed to append CA certificate")
		return
	}

	// Create TLS configuration
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	if testCase == "mtls_request_response" {
		fmt.Println("configuring for mTLS")
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	// Dial the server
	conn, err := tls.Dial("tcp", Host+":"+port, tlsConfig)
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}

	// Create reader and writer for the connection
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Perform handshake
	err = conn.Handshake()
	if err != nil {
		fmt.Println("Error during handshake:", err)
		return
	}
	fmt.Println("Handshake completed during testcase:", testCase)

	switch testCase {
	case "handshake":
		// No action required for handshake case
	case "greeting", "mtls_request_response":
		// Send client greeting
		fmt.Println("sending the client greeting")
		_, err = writer.WriteString(ClientGreeting)
		if err != nil {
			fmt.Println("Error writing data:", err)
			return
		}
		err = writer.Flush()
		if err != nil {
			fmt.Println("Error flushing data:", err)
			return
		}

		// Read and verify server greeting
		fmt.Println("reading the server response greeting")
		serverGreeting := make([]byte, len(ServerGreeting))
		_, err = io.ReadFull(reader, serverGreeting)
		//serverGreeting, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading data:", err)
			return
		}
		if string(serverGreeting) != ServerGreeting {
			fmt.Println("Unexpected server greeting")
			return
		}
	case "large_data_download", "large_data_download_with_frequent_key_updates":
		// Send client greeting
		_, err = writer.WriteString(ClientGreeting)
		if err != nil {
			fmt.Println("Error writing data:", err)
			return
		}
		err = writer.Flush()
		if err != nil {
			fmt.Println("Error flushing data:", err)
			return
		}

		// Read and verify large data download
		buffer := make([]byte, 1_000_000)
		for i := 0; i < LargeDataDownloadGB; i++ {
			for j := 0; j < 1_000; j++ {
				_, err := io.ReadFull(reader, buffer)
				if err != nil {
					fmt.Println("Error reading data:", err)
					return
				}
				// Check tag value
				if int(buffer[0]) != (i % 255) {
					fmt.Println("Unexpected tag value")
					return
				}
			}
		}
	default:
		fmt.Println("Unsupported test case")
		os.Exit(127)
		return
	}

	fmt.Println("closing the client side of the connection");
	conn.CloseWrite()
	
	fmt.Println("waiting for the server side to close");
	_, err = reader.ReadByte()
	if err != io.EOF {
		fmt.Println("unexpected error:", err)
		os.Exit(1)
	}


	fmt.Println("Test case completed successfully.")
}
