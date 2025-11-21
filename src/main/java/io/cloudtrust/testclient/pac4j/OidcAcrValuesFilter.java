package io.cloudtrust.testclient.pac4j;

import org.jetbrains.annotations.NotNull;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This class is used to get acr_values from the query parameters and add it to the oidc configuration
 */
public class OidcAcrValuesFilter extends OncePerRequestFilter {

    private final Config config;
    private final SecurityFilter securityFilter;

    public OidcAcrValuesFilter(Config config, SecurityFilter securityFilter) {
        this.config = config;
        this.securityFilter = securityFilter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {

        String acrValues = request.getParameter("acr_values");

        if (acrValues != null && !acrValues.isEmpty()) {
            // Get the OIDC client and update custom params
            Optional<Client> oidcClientOpt = config.getClients().findClient("oidcClient");
            if (oidcClientOpt.isPresent()) {
                OidcClient oidcClient = (OidcClient) oidcClientOpt.get();
                OidcConfiguration oidcConfig = oidcClient.getConfiguration();

                Map<String, String> customParams = new HashMap<>(oidcConfig.getCustomParams());
                customParams.put("acr_values", acrValues);
                oidcConfig.setCustomParams(customParams);
            }
        }

        securityFilter.doFilter(request, response, filterChain);
    }
}