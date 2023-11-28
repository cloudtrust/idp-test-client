package io.cloudtrust.testclient.config;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class CustomXmlSigOutInterceptor extends AbstractPhaseInterceptor<Message> {
    private static final Logger logger = LoggerFactory.getLogger(CustomXmlSigOutInterceptor.class);

    public CustomXmlSigOutInterceptor() {
        super(Phase.PRE_PROTOCOL);
    }

    @Override
    public void handleMessage(Message message) throws Fault {
        logger.warn("**** FPX: Handling message **** {}", message);
        if (message instanceof SoapMessage) {
            logger.warn("**** FPX: Handling message **** message is a SoapMessage");
            SoapMessage sm = (SoapMessage)message;
            String action = (String)sm.get("SOAPAction");
            if (action!=null && action.endsWith("/Renew")) {
                logger.warn("***** FPX ***** handlingMessage !!!!");
                Map<String, Object> outProps = new HashMap<>();
                outProps.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE); // Define the security action
                outProps.put(ConfigurationConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                outProps.put(ConfigurationConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256");

                WSS4JOutInterceptor wssOut = new WSS4JOutInterceptor(outProps);
                wssOut.handleMessage(sm);
            }
        }
    }
}