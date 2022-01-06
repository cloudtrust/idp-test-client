package io.cloudtrust.testclient.pac4j;

import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.saml.context.SAML2MessageContext;
import org.pac4j.saml.metadata.SAML2MetadataResolver;
import org.pac4j.saml.profile.api.SAML2ResponseValidator;
import org.pac4j.saml.sso.artifact.SAML2ArtifactBindingMessageReceiver;
import org.pac4j.saml.sso.artifact.SOAPPipelineProvider;
import org.pac4j.saml.transport.AbstractPac4jDecoder;

public class CustomSAML2ArtifactBindingMessageReceiver extends SAML2ArtifactBindingMessageReceiver {

    public CustomSAML2ArtifactBindingMessageReceiver(SAML2ResponseValidator validator, SAML2MetadataResolver idpMetadataResolver, SAML2MetadataResolver spMetadataResolver, SOAPPipelineProvider soapPipelineProvider, SAML2Configuration saml2Configuration) {
        super(validator, idpMetadataResolver, spMetadataResolver, soapPipelineProvider, saml2Configuration);
    }

    @Override
    public Credentials receiveMessage(final SAML2MessageContext context) {
        context.setSaml2Configuration(saml2Configuration);
        final SAMLPeerEntityContext peerContext = context.getSAMLPeerEntityContext();
        final WebContext webContext = context.getWebContext();

        peerContext.setRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        context.getSAMLSelfProtocolContext().setProtocol(SAMLConstants.SAML20P_NS);

        final AbstractPac4jDecoder decoder = getDecoder(webContext);

        final SAML2MessageContext decodedCtx = prepareDecodedContext(context, decoder);

        Credentials cred = this.validator.validate(decodedCtx);
        // CUSTOM: make the assertion available
        context.setSubjectAssertion(decodedCtx.getSubjectAssertion());
        return cred;
    }
}
