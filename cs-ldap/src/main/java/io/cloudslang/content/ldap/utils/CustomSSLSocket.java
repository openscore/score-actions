package io.cloudslang.content.ldap.utils;


import javax.net.SocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.Socket;

/**
 *
 * This class creates a tunnel through a proxy server to communicate to/from Active Directory Server using HTTP CONNECT method.
 *
 * Prerequisites :
 * Client application server has to trust Active Directory server.
 *          If Self signed certificate is used
 *              Client should have self signed certificate of the corresponding Active Direcotry server installed in its JVM
 *          If Public certificate is used
 *              No need to install anything on the client side.
 *      The proxy server should allow HTTP CONNECT method.
 *
 * @author dheeraj.gopali
 */
public class CustomSSLSocket extends SocketFactory {

    /**
     * Contains proxy server host name.
     */
    private static String tunnelHost;

    /**
     * Contains proxy server port number.
     */
    private static int tunnelPort;

    /**
     * Contains whether secured data or plain data is passed through tunnel.
     */
    private static boolean isSecured;

    public static void setTunnelHost(String tunnelHost) {
        CustomSSLSocket.tunnelHost = tunnelHost;
    }

    public static void setTunnelPort(int tunnelPort) {
        CustomSSLSocket.tunnelPort = tunnelPort;
    }

    public static void setIsSecured(boolean isSecured) {
        CustomSSLSocket.isSecured = isSecured;
    }

    @Override
    public Socket createSocket(String s, int i) throws IOException {
        return localCreateSocket(s, i);
    }

    @Override
    public Socket createSocket(String s, int i, InetAddress inetAddress, int i2) throws IOException {
        return localCreateSocket(s, i);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i) throws IOException {
        return localCreateSocket(inetAddress.getHostAddress(), i);
    }

    @Override
    public Socket createSocket(InetAddress inetAddress, int i, InetAddress inetAddress2, int i2) throws IOException {
        return localCreateSocket(inetAddress.getHostAddress(), i);
    }

    /**
     * Creates a new socket everty time. Based on {#isSecured} attribute, it creates SSLSocket or Simple socket.
     *
     * @param host Destination server host name. Here Active Directory host name.
     * @param port Destination server port number. If secured connection is used, its' default value is 636, else 389.
     * @return Socket object.
     * @throws IOException
     */
    private Socket localCreateSocket(String host, int port) throws IOException {
        Socket tunnel = new Socket(tunnelHost, tunnelPort);
        doTunnelHandshake(tunnel, host, port);
        if(isSecured) {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = null;
            //Overlay the tunnel socket with SSL.
            socket = (SSLSocket) factory.createSocket(tunnel, host, port, true);
            //Register a callback for handshaking completion event
            socket.startHandshake();
            return socket;
        }
        return tunnel;
    }

    /**
     * This method is invoked by JNDI while initiating connection to Active Directory.
     *
     * @return CustomSSLSocketFactory which contains a tunneling socket.
     */
    public static CustomSSLSocket getDefault() {
        return new CustomSSLSocket();
    }

    /**
     * This method does the initial handshake between source and destination via proxy server using CONNECT method.
     *
     * @param tunnel a regular socket to proxy server.
     * @param host Destination server/Active Directory host name.
     * @param port Destination server/Active Directory port number.
     *
     * @throws IOException
     */
    private void doTunnelHandshake(Socket tunnel, String host, int port)
            throws IOException {
        OutputStream out = tunnel.getOutputStream();
        String msg = "CONNECT " + host + ":" + port + " HTTP/1.0\n"
                + "User-Agent: " + sun.net.www.protocol.http.HttpURLConnection.userAgent + "\r\n\r\n";
        byte b[];
        try {
            //We really do want ASCII7 -- the http protocol doesn't change with locale.
            b = msg.getBytes("ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            //If ASCII7 isn't there, something serious is wrong, but Paranoia Is Good (tm)
            b = msg.getBytes();
        }
        out.write(b);
        out.flush();

        //We need to store the reply so we can create a detailed error message to the user.
        byte reply[] = new byte[200];
        int replyLen = 0;
        int newlinesSeen = 0;
        boolean headerDone = false;     /* Done on first newline */

        InputStream in = tunnel.getInputStream();
        boolean error = false;

        while (newlinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException("Unexpected EOF from proxy");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone & replyLen < reply.length) {
                    reply[replyLen++] = (byte) i;
                }
            }
        }

        /*
         * Converting the byte array to a string is slightly wasteful in the case where the connection was successful,
         * but it's insignificant compared to the network overhead.
         */
        String replyStr;
        try {
            replyStr = new String(reply, 0, replyLen, "ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            replyStr = new String(reply, 0, replyLen);
        }

        if (replyStr.toLowerCase().indexOf("200 connection established") == -1) {
            throw new IOException("Unable to tunnel through "+ tunnelHost + ":" + tunnelPort+ ".  Proxy returns \""
                    + replyStr + "\"");
        }
    }
}
