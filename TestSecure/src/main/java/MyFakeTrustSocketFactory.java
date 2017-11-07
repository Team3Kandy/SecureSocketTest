import com.hazelcast.nio.ssl.SSLContextFactory;
import org.apache.axis.components.logger.LogFactory;
import org.apache.axis.components.net.BooleanHolder;
import org.apache.axis.components.net.SecureSocketFactory;
import org.apache.axis.components.net.TransportClientProperties;
import org.apache.axis.components.net.TransportClientPropertiesFactory;
import org.apache.axis.utils.Messages;
import org.apache.axis.utils.StringUtils;
import org.apache.axis.utils.XMLUtils;
import org.apache.commons.logging.Log;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Socket;
import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

public class MyFakeTrustSocketFactory implements SecureSocketFactory {

    /** Field log           */
    protected static Log log =
            LogFactory.getLog(MyFakeTrustSocketFactory.class.getName());
    /**
     * Constructor JSSESocketFactory
     *
     * @param attributes
     */
    public MyFakeTrustSocketFactory(Hashtable attributes) {

    }

    /**
     * Method getContext
     *
     * @return
     *
     * @throws Exception
     */
    protected SSLContext getContext() throws Exception {

        try {
            SSLContext sc = SSLContext.getInstance("SSL");

            sc.init(null, // we don't need no stinkin KeyManager
                    new TrustManager[]{new MyFakeTrustSocketFactory.MyFakeX509TrustManager()},
                    new java.security.SecureRandom());
            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("My fake Socket Factory get context "));
            }
            return sc;
        } catch (Exception exc) {
            log.error(Messages.getMessage("My fake Socket Factory get context Exception"), exc);
            throw new Exception(Messages.getMessage("ftsf02"));
        }
    }
    protected SSLSocketFactory sslFactory = null;
    protected void initFactory() throws IOException {
        sslFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
    }
    /**
     * Create a socket
     *
     * @param host
     * @param port
     * @param otherHeaders
     * @param useFullURL
     * @return
     * @throws Exception
     */
    public Socket create(String host, int port, StringBuffer otherHeaders, BooleanHolder useFullURL) throws Exception {
        SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS","BCJSSE");
        String kf = "D:\\git_repos\\chap8.keystore";
     //   String keyStoreFilePath = "C:\\Program Files\\Java\\jdk1.8.0_144\\jre\\lib\\security\\cacerts";
        String keyStoreFilePassword = "changeit";
        File keystoreFile = new File(kf);
        if(!keystoreFile.exists() || keystoreFile.isDirectory())
            return null;

        KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
        FileInputStream fin = new FileInputStream(kf);
        keyStore.load(fin, keyStoreFilePassword.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        sslContext.init(null,
                tmf.getTrustManagers(),
                new java.security.SecureRandom() );
        sslFactory = sslContext.getSocketFactory();
        if (port == -1) {
            port = 443;
        }

        TransportClientProperties tcp = TransportClientPropertiesFactory.create("https");

        //boolean hostInNonProxyList = isHostInNonProxyList(host, tcp.getNonProxyHosts());
        boolean hostInNonProxyList = false;
        Socket sslSocket = null;
        if (tcp.getProxyHost().length() == 0 || hostInNonProxyList) {
            // direct SSL connection
            sslSocket = sslFactory.createSocket(host, port);
        }
        else {

            // Default proxy port is 80, even for https
            int tunnelPort = (tcp.getProxyPort().length() != 0)
                    ? Integer.parseInt(tcp.getProxyPort())
                    : 80;
            if (tunnelPort < 0)
                tunnelPort = 80;

            // Create the regular socket connection to the proxy
            Socket tunnel = new Socket(tcp.getProxyHost(), tunnelPort);

            // The tunnel handshake method (condensed and made reflexive)
            OutputStream tunnelOutputStream = tunnel.getOutputStream();
            PrintWriter out = new PrintWriter(
                    new BufferedWriter(new OutputStreamWriter(tunnelOutputStream)));

            // More secure version... engage later?
            // PasswordAuthentication pa =
            // Authenticator.requestPasswordAuthentication(
            // InetAddress.getByName(tunnelHost),
            // tunnelPort, "SOCK", "Proxy","HTTP");
            // if(pa == null){
            // printDebug("No Authenticator set.");
            // }else{
            // printDebug("Using Authenticator.");
            // tunnelUser = pa.getUserName();
            // tunnelPassword = new String(pa.getPassword());
            // }
            out.print("CONNECT " + host + ":" + port + " HTTP/1.0\r\n"
                    + "User-Agent: AxisClient");
            if (tcp.getProxyUser().length() != 0 &&
                    tcp.getProxyPassword().length() != 0) {

                // add basic authentication header for the proxy
                String encodedPassword = XMLUtils.base64encode((tcp.getProxyUser()
                        + ":"
                        + tcp.getProxyPassword()).getBytes());

                out.print("\nProxy-Authorization: Basic " + encodedPassword);
            }
            out.print("\nContent-Length: 0");
            out.print("\nPragma: no-cache");
            out.print("\r\n\r\n");
            out.flush();
            InputStream tunnelInputStream = tunnel.getInputStream();

            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("isNull00", "tunnelInputStream",
                        "" + (tunnelInputStream
                                == null)));
            }
            String replyStr = "";

            // Make sure to read all the response from the proxy to prevent SSL negotiation failure
            // Response message terminated by two sequential newlines
            int newlinesSeen = 0;
            boolean headerDone = false;    /* Done on first newline */

            while (newlinesSeen < 2) {
                int i = tunnelInputStream.read();

                if (i < 0) {
                    throw new IOException("Unexpected EOF from proxy");
                }
                if (i == '\n') {
                    headerDone = true;
                    ++newlinesSeen;
                } else if (i != '\r') {
                    newlinesSeen = 0;
                    if (!headerDone) {
                        replyStr += String.valueOf((char) i);
                    }
                }
            }
            if (StringUtils.startsWithIgnoreWhitespaces("HTTP/1.0 200", replyStr) &&
                    StringUtils.startsWithIgnoreWhitespaces("HTTP/1.1 200", replyStr)) {
                throw new IOException(Messages.getMessage("cantTunnel00",
                        new String[]{
                                tcp.getProxyHost(),
                                "" + tunnelPort,
                                replyStr}));
            }

            // End of condensed reflective tunnel handshake method
            sslSocket = sslFactory.createSocket(tunnel, host, port, true);
            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("setupTunnel00",
                        tcp.getProxyHost(),
                        "" + tunnelPort));
            }
        }

        ((SSLSocket) sslSocket).startHandshake();
        if (log.isDebugEnabled()) {
            log.debug(Messages.getMessage("createdSSL00"));
        }
        return sslSocket;
    }

    /**
     * Class FakeX509TrustManager
     */
    public static class MyFakeX509TrustManager implements X509TrustManager {

        /** Field log           */
        protected static Log log =
                LogFactory.getLog(MyFakeTrustSocketFactory.MyFakeX509TrustManager.class.getName());

        /**
         * Method isClientTrusted
         *
         * @param chain
         *
         * @return
         */
        public boolean isClientTrusted(java.security.cert
                                               .X509Certificate[] chain) {

            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("my fake trust manager is client trusted"));
            }
            return true;
        }

        /**
         * Method isServerTrusted
         *
         * @param chain
         *
         * @return
         */
        public boolean isServerTrusted(java.security.cert
                                               .X509Certificate[] chain) {

            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("my fake trust manager is server trusted"));
            }
            return true;
        }
        //TODO :
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            return;
        }
        //TODO :
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            return;
        }

        /**
         * Method getAcceptedIssuers
         *
         * @return
         */
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {

            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("My Fake Trust manager get accepted issuers"));
            }
            return null;
        }
    }
}
