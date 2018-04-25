package io.cloudtrust.testclient.pac4j;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Conditions;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.credentials.authenticator.SAML2Authenticator;
import org.pac4j.saml.profile.SAML2Profile;
import org.w3c.dom.Element;

import java.util.*;

/**
 * This class replaces the SAML2Authenticator with the sole purpose of correcting the validate method:
 * the default method cannot handle SAML assertions in which multiple attributes have the same name, whereas this one
 * can.
 */
public final class BetterSAML2Authenticator extends SAML2Authenticator {

    /**
     * Validate the credentials. It should throw a {@link CredentialsException} in case of failure.
     *
     * Correctly handles SAML assertions which have the same name
     *
     * @param credentials the given credentials
     * @param context the web context
     * @throws HttpAction requires a specific HTTP action if necessary
     * @throws CredentialsException the credentials are invalid
     */
    @Override
    public void validate(final SAML2Credentials credentials, final WebContext context) throws HttpAction, CredentialsException {
        init(context);

        final SAML2Profile profile = getProfileDefinition().newProfile();
        profile.setId(credentials.getNameId().getValue());
        profile.addAttribute(SESSION_INDEX, credentials.getSessionIndex());

        Map<String, Set<String>> attributes = new HashMap<>();

        for (final Attribute attribute : credentials.getAttributes()) {
            logger.debug("Processing profile attribute {}", attribute);

            final String name = attribute.getName();
            final String friendlyName = attribute.getFriendlyName();

            final String keyName = CommonHelper.isNotBlank(friendlyName)?friendlyName:name;

            if (!attributes.containsKey(keyName)){
                attributes.put(keyName, new HashSet<>());
            }
            for (final XMLObject attributeValue : attribute.getAttributeValues()) {
                final Element attributeValueElement = attributeValue.getDOM();
                if (attributeValueElement != null) {
                    final String value = attributeValueElement.getTextContent();
                    logger.debug("Adding attribute value {} for attribute {} / {}", value,
                            name, friendlyName);
                    attributes.get(keyName).add(value);
                } else {
                    logger.warn("Attribute value DOM element is null for {}", attribute);
                }
            }
        }
        for (String keyName: attributes.keySet()){
            List values = new ArrayList(attributes.get(keyName));
            if (!values.isEmpty()) {
                getProfileDefinition().convertAndAdd(profile, keyName, values);
            } else {
                logger.debug("No attribute values found for {}", keyName);
            }
        }

        // Retrieve conditions attributes
        Conditions conditions = credentials.getConditions();
        if (conditions != null) {
            profile.addAttribute(SAML_CONDITION_NOT_BEFORE_ATTRIBUTE, conditions.getNotBefore());
            profile.addAttribute(SAML_CONDITION_NOT_ON_OR_AFTER_ATTRIBUTE, conditions.getNotOnOrAfter());
        }

        credentials.setUserProfile(profile);
    }
}
