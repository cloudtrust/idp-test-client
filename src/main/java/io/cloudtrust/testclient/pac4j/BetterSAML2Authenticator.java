package io.cloudtrust.testclient.pac4j;

import org.apache.cxf.common.logging.LogUtils;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.credentials.authenticator.SAML2Authenticator;
import org.pac4j.saml.profile.SAML2Profile;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * This class replaces the SAML2Authenticator with the sole purpose of correcting the validate method:
 * the default method cannot handle SAML assertions in which multiple attributes have the same name, whereas this one
 * can.
 */
public final class BetterSAML2Authenticator extends SAML2Authenticator {
    private static final Logger log = LogUtils.getL7dLogger(BetterSAML2Authenticator.class);

    public BetterSAML2Authenticator() {
        super("userid", new HashMap<>());
    }

    /**
     * Validate the credentials. It should throw a {@link CredentialsException} in case of failure.
     * <p>
     * Correctly handles SAML assertions which have the same name
     *
     * @param cred    the given credentials
     * @param context the web context
     * @throws CredentialsException the credentials are invalid
     */
    @SuppressWarnings("unchecked")
    @Override
    public void validate(final Credentials cred, final WebContext context, final SessionStore sessionStore) {
        init();

        final SAML2Credentials credentials = (SAML2Credentials) cred;
        final SAML2Profile profile = (SAML2Profile) getProfileDefinition().newProfile();
        profile.setId(credentials.getNameId().getValue());
        profile.addAttribute(SESSION_INDEX, credentials.getSessionIndex());

        Map<String, Object> attributes = new HashMap<>();

        for (final SAML2Credentials.SAMLAttribute attribute : credentials.getAttributes()) {
            log.fine("Processing profile attribute "+attribute);

            final String name = attribute.getName();
            final String friendlyName = attribute.getFriendlyName();

            final String keyName = CommonHelper.isNotBlank(friendlyName) ? friendlyName : name;

            Set<String> a = (Set<String>) attributes.computeIfAbsent(keyName, k -> new HashSet<String>());
            a.addAll(attribute.getAttributeValues());
        }
        getProfileDefinition().convertAndAdd(profile, attributes, null);

        // Retrieve conditions attributes
        SAML2Credentials.SAMLConditions conditions = credentials.getConditions();
        if (conditions != null) {
            profile.addAttribute(SAML_CONDITION_NOT_BEFORE_ATTRIBUTE, conditions.getNotBefore());
            profile.addAttribute(SAML_CONDITION_NOT_ON_OR_AFTER_ATTRIBUTE, conditions.getNotOnOrAfter());
        }

        profile.addAuthenticationAttribute(SESSION_INDEX, credentials.getSessionIndex());
        if (context.getResponseHeader("saml_assertion").isPresent()) {
            profile.addAttribute("saml_assertion", context.getResponseHeader("saml_assertion").get());
        }
        credentials.setUserProfile(profile);
    }
}
