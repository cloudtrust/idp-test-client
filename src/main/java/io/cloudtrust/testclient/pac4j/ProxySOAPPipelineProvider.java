package io.cloudtrust.testclient.pac4j;

import io.cloudtrust.testclient.config.ProxyConfig;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import org.pac4j.saml.sso.artifact.DefaultSOAPPipelineProvider;

public class ProxySOAPPipelineProvider extends DefaultSOAPPipelineProvider {
    private final ProxyConfig proxyConfig;

    public ProxySOAPPipelineProvider(final CustomSAML2Client client) {
        super(client);
        this.proxyConfig = client.getProxyConfig();
    }

    @Override
    public HttpClientBuilder getHttpClientBuilder() {
        HttpClientBuilder builder = new HttpClientBuilder();

        if (proxyConfig.isProxyEnabled()) {
            builder.setConnectionProxyHost(proxyConfig.getProxyHost());
            builder.setConnectionProxyPort(proxyConfig.getProxyPort());
        }

        return builder;
    }
}
