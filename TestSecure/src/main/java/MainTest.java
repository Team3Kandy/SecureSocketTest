import com.genband.logging.userbasedlogger.Logger;
import com.nortelnetworks.ws.common.ProvisioningException;
import com.nortelnetworks.ws.serverinfo.ServerInfoUserIF;
import com.nortelnetworks.ws.serverinfo.ServerInfoUserServiceStub;
import org.apache.axis.AxisProperties;
import org.apache.axis.client.Stub;

import javax.xml.rpc.ServiceException;
import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.HashMap;

public class MainTest {

    public static void main(String argv[]) {
        System.err.println("Requesting server info user");
        A2SopiWSClient wsClient = new A2SopiServerInfoUserSvcWSClient();
        System.err.println("Response : " + makeWSCall("u1061@spidr.com", "1234", null, wsClient).values().toArray()[0]);

    }

    public static HashMap<String, Object> makeWSCall(String a2UserName,
                                                     String a2Password, Object[] obj, A2SopiWSClient... wsClients) {
        boolean allWSClientsDone = false;
        boolean nextA2 = false;
        boolean nextPA = false;
        URL paAddress = null;
        try {
            paAddress = new URL("https://47.168.116.9/sopi/services/ServerInfoUserService");
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        // TODO : set PA address
        Object response = null;
        A2SopiWSClient wsClient = wsClients[0];
        HashMap<String, Object> responses = new HashMap<String, Object>();
        // override SSL authentication if required

        AxisProperties.setProperty("axis.socketSecureFactory",
                "MyFakeTrustSocketFactory");
        try {
            response = wsClient.runService(paAddress, a2UserName, a2Password);
        } catch (RemoteException e) {
            e.printStackTrace();
        } catch (ServiceException e) {
            e.printStackTrace();
        }
        responses.put(wsClient.getClass().getName(), response);

        return responses;
    }

    interface A2SopiWSClient {
        Object runService(URL paAddress, String a2UserName, String a2Password) throws ServiceException,
                ProvisioningException, RemoteException;
    }

    public static class A2SopiServerInfoUserSvcWSClient implements A2SopiWSClient {
        protected Logger logger = Logger.getLogger(this.getClass().getName());
        private final String NAME = "ServerInfoUserService";

        private final String HTTP = "http://";
        private final String HTTPS = "https://";

        /**
         * Creates a new instance of A2SopiGABUserSvcWSClient
         */
        public A2SopiServerInfoUserSvcWSClient() {
            super();
        }




        /**
         * Get data from the PA
         */

        public Object runService(URL paAddress, String a2UserName, String a2Password) throws ServiceException,
                ProvisioningException, RemoteException {
            ServerInfoUserServiceStub stub = new ServerInfoUserServiceStub(paAddress,null);
            stub.setPortName("443");
            ServerInfoUserIF service = stub;
            Stub.class.cast(service).setUsername(a2UserName);
            Stub.class.cast(service).setPassword(a2Password);

            Stub.class.cast(service).setHeader("SOPI", "version", "1.0");

            Stub.class.cast(service)._setProperty(org.apache.axis.MessageContext.HTTP_TRANSPORT_VERSION,
                    org.apache.axis.transport.http.HTTPConstants.HEADER_PROTOCOL_V11);
            Stub.class.cast(service).setTimeout(5000);

                System.err.println("Used A2 getServices to get assigned services for  " + a2UserName + " from "
                        + paAddress.getHost() + ":" + paAddress.getPort());


            int paPort = service.getSOAPServerData().getHttpsPort();
            String paHttpHeader = HTTPS;

            if (paPort == 0) {
                paPort = service.getSOAPServerData().getHttpPort();
                paHttpHeader = HTTP;
            }

            return paHttpHeader + service.getSOAPServerData().getServerHostName() + ":" + paPort;
        }

    }
}
