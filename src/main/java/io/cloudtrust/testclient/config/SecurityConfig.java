package io.cloudtrust.testclient.config;

import io.cloudtrust.testclient.fediz.FederationConfigReader;
import io.cloudtrust.testclient.pac4j.OidcAcrValuesFilter;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationProvider;
import org.apache.cxf.fediz.spring.web.FederationAuthenticationEntryPoint;
import org.apache.cxf.fediz.spring.web.FederationAuthenticationFilter;
import org.apache.cxf.fediz.spring.web.FederationLogoutFilter;
import org.apache.cxf.fediz.spring.web.FederationSignOutCleanupFilter;
import org.pac4j.core.config.Config;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.pac4j.springframework.security.web.LogoutFilter;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.Filter;

/**
 * Spring security configuration of the pac4j (SAML, OIDC) and fediz (WSFED) libraries. The class is comprised of three
 * subclasses, as in spring security, in order to configure filters for different endpoints, it is necessary to subclass
 * {@link WebSecurityConfigurerAdapter} multiple times.
 */
@EnableWebSecurity
public class SecurityConfig {

    /**
     * This class contains the configuration of the access to the secured /secured controller for both the
     * fediz and pac4j libraries, and the logout filters for the fediz libraries
     */
    @Configuration
    @Order(1)
    protected static class ProtocolSecurityConfig extends WebSecurityConfigurerAdapter {
        @Value("${connection.protocol:WSFED}")
        private ProtocolType protocol;

        @Autowired
        private Config config;

        @Autowired
        private SessionFixationProtectionStrategy sas;
        @Autowired
        private FederationAuthenticationProvider federationAuthProvider;
        @Autowired
        private FederationAuthenticationEntryPoint federationEntryPoint;
        @Autowired
        private FederationLogoutFilter logoutFilter;
        @Autowired
        private FederationSignOutCleanupFilter federationSignOutCleanupFilter;

        /**
         * Creates the fediz filter bean
         *
         * @return the fediz filter bean
         * @throws Exception
         */
        @Bean
        public FederationAuthenticationFilter federationFilter() throws Exception {
            FederationAuthenticationFilter fedAuthFilter = new FederationAuthenticationFilter();
            fedAuthFilter.setAuthenticationManager(authenticationManager());
            fedAuthFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler());
            return fedAuthFilter;
        }

        /**
         * Equivalent the <sec:authentication-manager> configuration element. Only necessary for fediz.
         *
         * @param auth the {@link AuthenticationManagerBuilder} to use
         * @throws Exception required by overwritten method signature
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            if (protocol == ProtocolType.WSFED) {
                auth.authenticationProvider(federationAuthProvider);
            } else {
                super.configure(auth);
            }
        }

        /**
         * Equivalent to the <sec:http> configuration element. Used to set the filter and secured/unsecured patterns.
         * here set to match only the /secured/** endpoint.
         * <p>
         * The configuration for the single sign-on for all protocols is set here, as well as the configuration for
         * the single logout for the WS-Fed protocol.
         *
         * @param http http the {@link HttpSecurity} to modify
         * @throws Exception required by overwritten method signature
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {

            final CallbackFilter callbackFilter = new CallbackFilter(config);
            Filter filter = federationFilter();
            switch (protocol) {
                case OIDC:
                    SecurityFilter securityFilter = new SecurityFilter(config, "oidcClient");
                    filter = new OidcAcrValuesFilter(config, securityFilter);
                    break;
                case SAML:
                    filter = new SecurityFilter(config, "CustomSaml2Client");
                    break;
            }

            if (protocol == ProtocolType.WSFED) {
                http.exceptionHandling().authenticationEntryPoint(federationEntryPoint)
                        .and()
                        .sessionManagement().sessionAuthenticationStrategy(sas)
                        .and()
                        .addFilterAt(logoutFilter, org.springframework.security.web.authentication.logout.LogoutFilter.class)
                        .addFilterAt(federationSignOutCleanupFilter, J2eePreAuthenticatedProcessingFilter.class);
            } else {
                http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
            }

            http.antMatcher("/secured/**").authorizeRequests()
                    .antMatchers("/secured/**").authenticated()
                    .and()
                    .addFilterBefore(filter, BasicAuthenticationFilter.class);
        }
    }


    /**
     * This class contains the configuration of the single logout filters for the pac4j library.
     */
    @Configuration
    @Order(2)
    public static class SingleLogoutConfig extends WebSecurityConfigurerAdapter {

        @Value("${connection.address:http://localhost:7000}")
        private String connectionAddress;
        @Value("${connection.protocol:WSFED}")
        private String connectionProtocol;

        @Autowired
        private Config config;
        @Autowired
        private FederationConfigReader fedizConfig;

        private ProtocolType protocol;

        /**
         * Equivalent to the <sec:http> configuration element. Used to set the filter and secured/unsecured patterns.
         * here set to match only the /singleSignout endpoint.
         * <p>
         * Configures only the pac4j logout element. For ws-fed, this only redirects to the ws-fed single logout
         * endpoint.
         *
         * @param http http the {@link HttpSecurity} to modify
         * @throws Exception required by overwritten method signature
         */
        protected void configure(final HttpSecurity http) throws Exception {

            boolean isWsFed = protocol == ProtocolType.WSFED;
            String logoutPath = isWsFed ? fedizConfig.getFedizContext().getLogoutURL() : "?defaulturlafterlogoutafteridp";
            String logoutAddress = isWsFed ? fedizConfig.getFedizContext().getAudienceUris().get(0) : connectionAddress;
            if (!logoutAddress.endsWith("/") && !logoutPath.startsWith("/")) {
                logoutAddress += "/";
            }


            final LogoutFilter filter = new LogoutFilter(config, logoutAddress + logoutPath);
            filter.setLocalLogout(!isWsFed);
            filter.setDestroySession(!isWsFed);
            filter.setCentralLogout(!isWsFed);
            fedizConfig.getFedizContext().getAudienceUris().get(0);
            filter.setLogoutUrlPattern(logoutAddress + ".*");

            http
                    .antMatcher("/singleLogout")
                    .addFilterBefore(filter, BasicAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
        }
    }

    /**
     * This class contains the configuration all other endpoints. This includes the configuration of callback filter for
     * the pac4j library, as well as the default logout logic for spring security.
     */
    @Configuration
    @Order(3)
    protected static class CallbackConfig extends WebSecurityConfigurerAdapter {

        @Autowired
        private Config config;

        /**
         * Equivalent to the <sec:http> configuration element. Used to set the filter and secured/unsecured patterns.
         * here set to match all other requests
         * <p>
         * The configuration of the callback filter for pac4j is set done here, as well as the standard logic for
         * a spring security logout.
         *
         * @param http http the {@link HttpSecurity} to modify
         * @throws Exception required by overwritten method signature
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            final CallbackFilter callbackFilter = new CallbackFilter(config);

            http.authorizeRequests()
                    .anyRequest().permitAll()
                    .and()
                    .addFilterBefore(callbackFilter, BasicAuthenticationFilter.class)
                    .csrf().disable()
                    .logout()
                    .logoutUrl("/performLogout")
                    .logoutSuccessUrl("/logout");
        }
    }

}
