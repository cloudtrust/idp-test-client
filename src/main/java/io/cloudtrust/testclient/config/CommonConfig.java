package io.cloudtrust.testclient.config;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import io.cloudtrust.testclient.fediz.FederationConfigReader;
import io.cloudtrust.testclient.pac4j.BetterSAML2Authenticator;
import io.cloudtrust.testclient.pac4j.CustomAuthorizer;
import io.cloudtrust.testclient.pac4j.CustomSAML2Client;
import io.cloudtrust.testclient.saml.SamlResponseBindingType;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationProvider;
import org.apache.cxf.fediz.spring.authentication.GrantedAuthoritiesUserDetailsFederationService;
import org.apache.cxf.fediz.spring.web.FederationAuthenticationEntryPoint;
import org.apache.cxf.fediz.spring.web.FederationLogoutFilter;
import org.apache.cxf.fediz.spring.web.FederationLogoutSuccessHandler;
import org.apache.cxf.fediz.spring.web.FederationSignOutCleanupFilter;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.pac4j.core.authorization.authorizer.RequireAnyRoleAuthorizer;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;

import java.io.File;
import java.util.Optional;

/**
 * Common spring configuration for beans required for the fediz and Pac4j libraries, using annotations rather than
 * the xml format
 */
@Configuration
public class CommonConfig {

    @Value("${connection.address:http://localhost:7000}")
    private String connectionAddress;

    /*The path to the fediz configuration file. By default set to the empty string, to get the local file*/
    @Value("${fediz.configFilePath:}")
    private String configFilePath;

    @Value("${saml.entityId:SAMLTestClient}")
    private String samlEntityId;
    @Value("${saml.keystorePath:resource:localstore.jks}")
    private String samlKeystorePath;
    @Value("${saml.keystorePassword:localpass}")
    private String samlKeystorePassword;
    @Value("${saml.privateKeyPassword:localpass}")
    private String samlPrivateKeyPassword;
    @Value("${saml.identityProviderMetadataPath:resource:SAMLIDP.xml}")
    private String samlIdentityProviderMetadataPath;
    @Value("${saml.responseBindingType:ARTIFACT}")
    private SamlResponseBindingType samlResponseBindingType;


    @Value("${oidc.uri:http://localhost:8080/realms/TestRealm/.well-known/openid-configuration}")
    private String oidcURI;
    @Value("${oidc.clientId:OIDCTestClient}")
    private String oidcClientId;
    @Value("${oidc.secret:aSecret}")
    private String oidcSecret;
    @Value("${oidc.scopes:openid}")
    private String oidcScopes;

    /**
     * Creates the bean for the pac4j configuration
     *
     * @return a pac4j configuration bean
     */
    @Bean
    public Config config() {
        final SAML2Configuration cfg = new SAML2Configuration(samlKeystorePath,
                samlKeystorePassword,
                samlPrivateKeyPassword,
                samlIdentityProviderMetadataPath);
        cfg.setMaximumAuthenticationLifetime(3600);
        cfg.setServiceProviderEntityId(samlEntityId);
        cfg.setServiceProviderMetadataPath(new File("samlSPMetadata.xml").getAbsolutePath());
        cfg.setAuthnRequestSigned(true);
        cfg.setSpLogoutRequestSigned(true);
        switch (samlResponseBindingType) {
            case ARTIFACT:
                cfg.setResponseBindingType(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
                break;
            case POST:
                cfg.setResponseBindingType(SAMLConstants.SAML2_POST_BINDING_URI);
                break;
            case REDIRECT:
                cfg.setResponseBindingType(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                break;
        }
        final ProxyConfig proxyConfig = new ProxyConfig();
        final SAML2Client saml2Client = new CustomSAML2Client(cfg, proxyConfig);
        saml2Client.setAuthenticator(new BetterSAML2Authenticator());

        final OidcConfiguration oidcConfiguration = new OidcConfiguration();
        oidcConfiguration.setDiscoveryURI(oidcURI);
        oidcConfiguration.setClientId(oidcClientId);
        oidcConfiguration.setSecret(oidcSecret);
        oidcConfiguration.setClientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        oidcConfiguration.setScope(oidcScopes);
        final OidcClient oidcClient = new OidcClient(oidcConfiguration);
        oidcClient.addAuthorizationGenerator((ctx, session, profile) -> {
            profile.addRole("ROLE_ADMIN");
            return Optional.of(profile);
        });

        if (!connectionAddress.endsWith("/")) {
            connectionAddress += "/";
        }
        final Clients clients = new Clients(connectionAddress + "callback", oidcClient, saml2Client);


        final Config config = new Config(clients);
        config.addAuthorizer("admin", new RequireAnyRoleAuthorizer("ROLE_ADMIN"));
        config.addAuthorizer("custom", customAuthorizer());
        return config;
    }

    /**
     * Creates the authorizer bean used by pac4j
     *
     * @return
     */
    @Bean
    public CustomAuthorizer customAuthorizer() {
        return new CustomAuthorizer();
    }


    /* --- Start of beans for fediz single sign-on configuration --- */
    @Bean
    public FederationConfigReader fedizConfig() {
        FederationConfigReader federationConfig = new FederationConfigReader();
        Resource config;
        if (configFilePath == null || configFilePath.isEmpty()) {
            config = new ClassPathResource("fediz_config.xml");
        } else {
            config = new FileSystemResource(configFilePath);
        }
        federationConfig.setConfigFile(config);
        federationConfig.setRelativePath("");
        federationConfig.setMainContextName("/");
        federationConfig.init();
        return federationConfig;
    }

    @Bean
    public FederationAuthenticationEntryPoint federationEntryPoint() {
        FederationAuthenticationEntryPoint fedAuthEntryPoint = new FederationAuthenticationEntryPoint();
        fedAuthEntryPoint.setFederationConfig(fedizConfig());
        return fedAuthEntryPoint;
    }

    @Bean
    public FederationAuthenticationProvider federationAuthProvider() {
        FederationAuthenticationProvider fedAuthProvider = new FederationAuthenticationProvider();
        fedAuthProvider.setFederationConfig(fedizConfig());
        fedAuthProvider.setAuthenticationUserDetailsService(new GrantedAuthoritiesUserDetailsFederationService());
        return fedAuthProvider;
    }


    @Bean
    public SessionFixationProtectionStrategy sas() {
        return new SessionFixationProtectionStrategy();
    }
    /* --- End of beans for fediz single sign-on configuration --- */

    /* --- Start of beans for fediz single logout configuration --- */
    @Bean
    public FederationSignOutCleanupFilter federationSignOutCleanupFilter() {
        return new FederationSignOutCleanupFilter();
    }

    @Bean
    public SecurityContextLogoutHandler securityContextLogoutHandler() {
        return new SecurityContextLogoutHandler();
    }

    @Bean
    public FederationLogoutSuccessHandler federationLogoutSuccessHandler() {
        FederationLogoutSuccessHandler fedLogoutSuccHandl = new FederationLogoutSuccessHandler();
        fedLogoutSuccHandl.setFederationConfig(fedizConfig());
        return fedLogoutSuccHandl;
    }

    @Bean
    public FederationLogoutFilter logoutFilter() {
        FederationLogoutFilter logoutFilter = new FederationLogoutFilter(federationLogoutSuccessHandler(),
                securityContextLogoutHandler());
        logoutFilter.setFederationConfig(fedizConfig());
        return logoutFilter;
    }
    /* --- End of beans for fediz single logout configuration --- */

}
