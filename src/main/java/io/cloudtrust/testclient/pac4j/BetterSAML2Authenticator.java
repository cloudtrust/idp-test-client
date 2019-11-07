package io.cloudtrust.testclient.pac4j;

import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.credentials.authenticator.SAML2Authenticator;
import org.pac4j.saml.profile.SAML2Profile;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class replaces the SAML2Authenticator with the sole purpose of correcting the validate method:
 * the default method cannot handle SAML assertions in which multiple attributes have the same name, whereas this one
 * can.
 */
public final class BetterSAML2Authenticator extends SAML2Authenticator {

    public BetterSAML2Authenticator() {
        super("userid", new HashMap<>());
    }

    /**
     * Validate the credentials. It should throw a {@link CredentialsException} in case of failure.
     * <p>
     * Correctly handles SAML assertions which have the same name
     *
     * @param credentials the given credentials
     * @param context     the web context
     * @throws HttpAction           requires a specific HTTP action if necessary
     * @throws CredentialsException the credentials are invalid
     */
    @SuppressWarnings("unchecked")
    @Override
    public void validate(final SAML2Credentials credentials, final WebContext context) {
        init();

        final SAML2Profile profile = getProfileDefinition().newProfile();
        profile.setId(credentials.getNameId().getValue());
        profile.addAttribute(SESSION_INDEX, credentials.getSessionIndex());

        Map<String, Object> attributes = new HashMap<>();

        for (final SAML2Credentials.SAMLAttribute attribute : credentials.getAttributes()) {
            logger.debug("Processing profile attribute {}", attribute);

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

        credentials.setUserProfile(profile);
    }
}
