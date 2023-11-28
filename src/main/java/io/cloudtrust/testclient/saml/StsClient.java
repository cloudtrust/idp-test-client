package io.cloudtrust.testclient.saml;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.common.logging.LogUtils;
import org.apache.cxf.ext.logging.LoggingInInterceptor;
import org.apache.cxf.ext.logging.LoggingOutInterceptor;
import org.apache.cxf.interceptor.Interceptor;
import org.apache.cxf.message.Message;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.http.client.utils.URIBuilder;
import org.apache.wss4j.common.ConfigurationConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import io.cloudtrust.testclient.config.CustomXmlSigOutInterceptor;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Controller
public class StsClient {
    private static final Logger logger = LoggerFactory.getLogger(StsClient.class);

    @Value("${saml.sts.wsdl}")
    private String samlStsUrl;

    public String renewAssertion(String assertion) throws Exception {
        logger.warn("**** FPX **** renewAssertion {}", assertion);
        // deserialize assertion to XML node
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(assertion));
        Document doc = builder.parse(is);
        Node assertionNode = doc.getFirstChild();

        SecurityToken token = new SecurityToken("123", (Element) assertionNode, Instant.now(), Instant.now());
        STSClient stsClient = createSTSClient();
        stsClient.getOutInterceptors().add(new CustomXmlSigOutInterceptor());
        for(Interceptor<? extends Message> inint : stsClient.getInInterceptors()) {
            logger.warn("** IN INTERCEPTOR ** {}", inint);
        }
        for(Interceptor<? extends Message> outint : stsClient.getOutInterceptors()) {
            logger.warn("** OUT INTERCEPTOR ** {}", outint);
        }
        stsClient.getOutInterceptors().add(new LoggingOutInterceptor());
        stsClient.getInInterceptors().add(new LoggingInInterceptor());

        SecurityToken securityToken2 = stsClient.renewSecurityToken(token);
        return xmlToString(securityToken2.getToken());
    }

    private STSClient createSTSClient() throws URISyntaxException {
        URIBuilder uriWsdlBuilder = new URIBuilder(samlStsUrl);

        // By default, SHA1 is used... Let's change to SHA256
        Map<String, Object> props = new HashMap<>();
        //props.put("signature.algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        //props.put("signature.digest.algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        //props.put("rs.security.http.signature.algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        //props.put("rs.security.http.signature.digest.algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
        props.put(ConfigurationConstants.SIG_ALGO, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        props.put(ConfigurationConstants.SIG_DIGEST_ALGO, "http://www.w3.org/2001/04/xmlenc#sha256");

        Bus bus = BusFactory.getThreadDefaultBus();
        STSClient stsClient = new STSClient(bus);
        stsClient.setProperties(props);
        stsClient.getRequestContext().putAll(props);
        stsClient.getRequestContext().put("security.signature.properties", "sts-client-crypto.properties");
        stsClient.setWsdlLocation(uriWsdlBuilder.build().toString());
        stsClient.setServiceName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}SecurityTokenService");
        stsClient.setEndpointName("{http://docs.oasis-open.org/ws-sx/ws-trust/200512/}Transport_Port");
        String tokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
        stsClient.setTokenType(tokenType);
        stsClient.setKeyType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        stsClient.setAllowRenewingAfterExpiry(false);
        stsClient.setEnableLifetime(true);
        stsClient.setEnableAppliesTo(true);
        stsClient.setRequiresEntropy(true);
        stsClient.setKeySize(256);
        stsClient.setAddressingNamespace("http://www.w3.org/2005/08/addressing");
        stsClient.setSendRenewing(true);
        stsClient.setTtl(300);

        return stsClient;
    }

    public static String xmlToString(Element e) {
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(e);
            StreamResult result = new StreamResult(new StringWriter());
            transformer.transform(source, result);
            return result.getWriter().toString();
        } catch (TransformerException ex) {
            logger.warn("Failed to convert xml to string", ex);
            return "<error while marshalling to string>";
        }
    }
}
