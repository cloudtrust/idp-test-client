package io.cloudtrust.testclient.pac4j;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.impl.AssertionMarshaller;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.context.SAML2MessageContext;
import org.pac4j.saml.credentials.extractor.SAML2CredentialsExtractor;
import org.w3c.dom.Element;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.Optional;

public class CustomSAML2CredentialsExtractor extends SAML2CredentialsExtractor {

    public CustomSAML2CredentialsExtractor(SAML2Client client) {
        super(client);
    }

    @Override
    protected Optional<Credentials> receiveLogin(final SAML2MessageContext samlContext, final WebContext context) {
        samlContext.setSaml2Configuration(saml2Client.getConfiguration());
        final Credentials credentials = this.profileHandler.receive(samlContext);

        // CUSTOM:
        try {
            Assertion assertion = samlContext.getSubjectAssertion();
            if (assertion != null) {
                AssertionMarshaller marshaller = new AssertionMarshaller();
                Element plaintextElement = marshaller.marshall(assertion);
                String originalAssertionString = xmlToString(plaintextElement);
                context.setResponseHeader("saml_assertion", originalAssertionString);
            }
        } catch (MarshallingException | TransformerException e) {
            System.err.println("Unexpected issue while marshalling the assertion to String");
            e.printStackTrace();
        }

        return Optional.ofNullable(credentials);
    }

    private String xmlToString(Element xml) throws TransformerException {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(xml);
        StreamResult result = new StreamResult(new StringWriter());
        transformer.transform(source, result);
        return result.getWriter().toString();
    }
}
