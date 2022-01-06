package io.cloudtrust.testclient.config;

/**
 * Enum of the protocol types supported by this test client
 */
public enum ProtocolType {
    WSFED, OIDC, SAML;

    public static ProtocolType valueFrom(String value) {
        try {
            return ProtocolType.valueOf(value);
        } catch (Exception e) {
            return WSFED;
        }
    }
}
