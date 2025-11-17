
package io.cloudtrust.testclient.config;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;

public class ProxyConfig {
    private final String proxyHost;
    private final int proxyPort;

    public ProxyConfig() {
        this.proxyHost = System.getProperty("https.proxyHost");
        this.proxyPort = NumberUtils.toInt(System.getProperty("https.proxyPort"));
    }

    public boolean isProxyEnabled() {
        return StringUtils.isNotBlank(proxyHost) && proxyPort > 0;
    }

    public String getProxyHost() {
        return proxyHost;
    }

    public int getProxyPort() {
        return proxyPort;
    }
}