package io.cloudtrust.testclient.pac4j;

import org.apache.commons.lang3.StringUtils;
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

    private static final String ACR_VALUES_PARAM = "acr_values";

    // Lock to protect configuration modifications
    private static final Object ACR_VALUES_LOCK = new Object();

    public OidcAcrValuesFilter(Config config, SecurityFilter securityFilter) {
        this.config = config;
        this.securityFilter = securityFilter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {

        String acrValues = request.getParameter(ACR_VALUES_PARAM);

        synchronized (ACR_VALUES_LOCK) {
            // Get the OIDC client and update custom params
            Optional<Client> oidcClientOpt = config.getClients().findClient("oidcClient");
            if (oidcClientOpt.isPresent()) {
                OidcClient oidcClient = (OidcClient) oidcClientOpt.get();
                OidcConfiguration oidcConfig = oidcClient.getConfiguration();

                oidcConfig.getCustomParams().remove(ACR_VALUES_PARAM);
                if (!StringUtils.isBlank(acrValues)) {
                    Map<String, String> customParams = new HashMap<>(oidcConfig.getCustomParams());
                    customParams.put(ACR_VALUES_PARAM, acrValues);
                    oidcConfig.setCustomParams(customParams);
                }
            }

            securityFilter.doFilter(request, response, filterChain);
        }
    }
}