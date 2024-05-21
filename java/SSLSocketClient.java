import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;

/*
* Simple JDK SSL client for interop testing purposes
*/

public class SSLSocketClient {
    static final int LARGE_DATA_DOWNLOAD_GB = 256;
    static final String TLS_13 = "TLSv1.3";
    static final String CLIENT_GREETING = "i am the client. nice to meet you server.";
    static final String SERVER_GREETING = "i am the server. a pleasure to make your acquaintance.";
    static final String HOST = "localhost";

    public static void main(String[] args) throws Exception {
        // enable debug logging for better visibility into SSL and TLS internals
        System.setProperty("javax.net.debug", "ssl");

        // parse the test arguments
        String testCase = args[0];
        int port = Integer.parseInt(args[1]);

        String certificatePath = "../certificates/ca-cert.pem";
        SSLSocketFactory socketFactory = createSocketFactory(certificatePath, TLS_13);
        try (
            SSLSocket socket = (SSLSocket)socketFactory.createSocket(HOST, port);
        ) {
            InputStream in = new BufferedInputStream(socket.getInputStream());
            OutputStream out = new BufferedOutputStream(socket.getOutputStream());

            socket.startHandshake();
            System.out.println("handshake completed during testcase: " + testCase);

            if (testCase.equals("handshake")) {
                // no action required for handshake case
            } else if (testCase.equals("greeting")) {
                out.write(CLIENT_GREETING.getBytes());
                out.flush();

                byte[] buffer = in.readNBytes(SERVER_GREETING.getBytes().length);
                
                String s = new String(buffer);
                if (!s.equals(SERVER_GREETING)) {
                    throw new Exception("Unexpected server greeting");
                }
            } else if (testCase.equals("large_data_download") || testCase.equals("large_data_download_with_frequent_key_updates")) {
                out.write(CLIENT_GREETING.getBytes());
                out.flush();
                byte[] buffer = new byte[1_000_000];
                for (int i = 0; i < LARGE_DATA_DOWNLOAD_GB; i++) {
                    for (int j = 0; j < 1_000; j++) {
                        int len = in.readNBytes(buffer, 0, 1_000_000);
                        if (len != 1_000_000) {
                            throw new Exception("Unexpected end of stream");
                        }
                        // java bytes are signed, so we have to upcast to an int to 
                        // read the tag value
                        int tag = buffer[0] & 0xFF;
                        if (tag != (i % 255)) {
                            System.out.println("unexpected tag value. Mb:" +(i * 1_000 + j) +" Expected:" + i + " received:" + tag);
                            System.out.println("unexpected tag value. Expected:" + i + " received:" + tag);
                            throw new Exception("Unexpected tag value");
                        }
                    }
                }
            } else {
                // unsupported test case
                System.exit(127);
            }
            // close the client side of the connection
            System.out.println("closing the client side of the connection");
            out.flush();
            // this sends both a TLS close notify and a TCP close? fin?
            //out.close();
            // using out.close() will trigger a duplex close of the SSLSocket, use
            // shutdownOutput instead.
            socket.shutdownOutput();


            // wait for the server to close it's side of the connection
            // read -1 if the end of the stream is reached
            // https://docs.oracle.com/javase/8/docs/api/java/io/InputStream.html#read--
            System.out.println("waiting for the server to close");
            int closed = in.read();
            if (closed != -1) {
                throw new Exception("server side unexpectedly open");
            }
        }
    }

    public static SSLSocketFactory createSocketFactory(String certificatePath, String protocol) {

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            FileInputStream is = new FileInputStream(certificatePath);

            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(is);
            is.close();

            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(null, null);
            caKeyStore.setCertificateEntry("ca-certificate", cert);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(caKeyStore);

            SSLContext context = SSLContext.getInstance(protocol);
            context.init(null, trustManagerFactory.getTrustManagers(), null);

            return context.getSocketFactory();

        } catch(Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
