package io.cloudtrust.testclient.pac4j;

import io.cloudtrust.testclient.config.ProxyConfig;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.saml.credentials.authenticator.SAML2Authenticator;
import org.pac4j.saml.logout.SAML2LogoutActionBuilder;
import org.pac4j.saml.metadata.SAML2IdentityProviderMetadataResolver;
import org.pac4j.saml.profile.api.SAML2MessageReceiver;
import org.pac4j.saml.redirect.SAML2RedirectionActionBuilder;
import org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver;
import org.pac4j.saml.sso.impl.SAML2WebSSOMessageSender;
import org.pac4j.saml.sso.impl.SAML2WebSSOProfileHandler;

import java.net.InetSocketAddress;
import java.net.Proxy;

import static org.pac4j.core.util.CommonHelper.assertNotNull;

public class CustomSAML2Client extends SAML2Client {
    private final ProxyConfig proxyConfig;

    public CustomSAML2Client(final SAML2Configuration configuration, final ProxyConfig proxyConfig) {
        super(configuration);
        this.proxyConfig = proxyConfig;
    }

    public ProxyConfig getProxyConfig() {
        return proxyConfig;
    }

    @Override
    protected void internalInit(boolean forceReinit) {
        assertNotNull("configuration", this.configuration);

        // First of all, initialize the configuration. It may dynamically load some properties, if it is not a static one.
        final String callbackUrl = computeFinalCallbackUrl(null);
        configuration.setCallbackUrl(callbackUrl);
        configuration.init();

        initDecrypter();
        initSignatureSigningParametersProvider();
        initIdentityProviderMetadataResolver();
        initServiceProviderMetadataResolver();
        initSAMLContextProvider();
        initSignatureTrustEngineProvider();
        initSAMLReplayCache();
        initSAMLResponseValidator();
        initSOAPPipelineProvider();
        initSAMLProfileHandler();
        initSAMLLogoutResponseValidator();
        initSAMLLogoutProfileHandler();

        defaultRedirectionActionBuilder(new SAML2RedirectionActionBuilder(this));
        defaultCredentialsExtractor(new CustomSAML2CredentialsExtractor(this));
        defaultAuthenticator(new SAML2Authenticator(this.configuration.getAttributeAsId(), this.configuration.getMappedAttributes()));
        defaultLogoutActionBuilder(new SAML2LogoutActionBuilder(this));
    }

    @Override
    protected void initIdentityProviderMetadataResolver() {
        this.idpMetadataResolver = this.configuration.getIdentityProviderMetadataResolver();

        if (proxyConfig.isProxyEnabled()) {
            InetSocketAddress proxyAddress = new InetSocketAddress(proxyConfig.getProxyHost(), proxyConfig.getProxyPort());
            Proxy javaNetProxy = new Proxy(Proxy.Type.HTTP, proxyAddress);
            ((SAML2IdentityProviderMetadataResolver) this.idpMetadataResolver).setProxy(javaNetProxy);
        }

        ((SAML2IdentityProviderMetadataResolver) this.idpMetadataResolver).init();
    }

    @Override
    protected void initSAMLProfileHandler() {
        final SAML2MessageReceiver messageReceiver;
        if (configuration.getResponseBindingType().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
            messageReceiver = new SAML2WebSSOMessageReceiver(this.authnResponseValidator, this.configuration);
        } else if (configuration.getResponseBindingType().equals(SAMLConstants.SAML2_ARTIFACT_BINDING_URI)) {
            messageReceiver = new CustomSAML2ArtifactBindingMessageReceiver(this.authnResponseValidator,
                    this.idpMetadataResolver, this.spMetadataResolver, this.soapPipelineProvider, this.configuration);
        } else {
            throw new TechnicalException(
                    "Unsupported response binding type: " + configuration.getResponseBindingType());
        }

        this.profileHandler = new SAML2WebSSOProfileHandler(
                new SAML2WebSSOMessageSender(this.signatureSigningParametersProvider,
                        this.configuration.getAuthnRequestBindingType(),
                        true,
                        this.configuration.isAuthnRequestSigned()),
                messageReceiver);
    }

    @Override
    protected void initSOAPPipelineProvider() {
        this.soapPipelineProvider = new ProxySOAPPipelineProvider(this);
    }
}
