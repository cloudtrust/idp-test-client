package io.cloudtrust.testclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.cloudtrust.testclient.config.ProtocolType;
import io.cloudtrust.testclient.pac4j.CustomSAML2Client;
import io.cloudtrust.testclient.saml.SamlResponseBindingType;
import io.cloudtrust.testclient.saml.StsClient;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.messaging.SAMLMessageSecuritySupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.util.FindBest;
import org.pac4j.jee.context.JEEContextFactory;
import org.pac4j.jee.context.session.JEESessionStore;
import org.pac4j.saml.context.SAML2MessageContext;
import org.pac4j.saml.crypto.DefaultSignatureSigningParametersProvider;
import org.pac4j.saml.logout.impl.SAML2LogoutRequestBuilder;
import org.pac4j.saml.profile.SAML2Profile;
import org.pac4j.springframework.security.authentication.Pac4jAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.w3c.dom.Element;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION;

@Controller
public class TokenInfoController {

    private final static String SOAP11_STRUCTURE =
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
                    " <SOAP-ENV:Body>${BODY}</SOAP-ENV:Body>" +
                    "</SOAP-ENV:Envelope>";

    @Value("${connection.protocol:WSFED}")
    private ProtocolType protocol;
    @Value("${saml.responseBindingType:ARTIFACT}")
    private SamlResponseBindingType samlResponseBindingType;

    @Autowired
    private StsClient stsCLient;

    @Autowired
    private Config config;

    @GetMapping(value = "/")
    public String home(Model model, HttpServletRequest req) {
        model.addAttribute("principal", req.getUserPrincipal());
        return "index";
    }

    @GetMapping(value = "/secured")
    public String authenticated(Model model, HttpServletRequest req) {
        model.addAttribute("principal", req.getUserPrincipal());
        model.addAttribute("tokenInfo", buildTokenInfo(req.getUserPrincipal(), req.getSession()));
        model.addAttribute("samlArtifactBinding", protocol == ProtocolType.SAML && samlResponseBindingType == SamlResponseBindingType.ARTIFACT);
        return "index";
    }

    @GetMapping(value = "/samlRenew")
    public String renewAssertion(Model model, HttpServletRequest req) throws Exception {
        String initialAssertion = new String(Base64.getDecoder().decode((String) req.getSession().getAttribute("saml_assertion")), StandardCharsets.UTF_8);
        String newAssertion = stsCLient.renewAssertion(initialAssertion);
        req.getSession().setAttribute("saml_assertion", Base64.getEncoder().encodeToString(newAssertion.getBytes(StandardCharsets.UTF_8)));
        return authenticated(model, req);
    }

    private String buildTokenInfo(Principal p, HttpSession session) {
        StringBuilder out = new StringBuilder();

        if (p != null) {
            out.append("User\n" +
                    "Principal: " + p.getName() + "\n");
        } else {
            out.append("Missing user principal information\n");
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        auth.getCredentials();
        if (auth instanceof FederationAuthenticationToken) {
            FederationAuthenticationToken fedAuthToken = (FederationAuthenticationToken) auth;
            out.append("Recognised claims:\n");
            for (Claim claim : fedAuthToken.getClaims()) {
                if (claim.getValue() instanceof Iterable) {
                    for (Object value : (Iterable<?>) claim.getValue()) {
                        out.append("    " + claim.getClaimType() + ": " + value + "\n");
                    }
                } else {
                    out.append("    " + claim.getClaimType() + ": " + claim.getValue() + "\n");
                }
            }
            out.append("\n");

            out.append("Raw token:\n");
            if (fedAuthToken.getCredentials() instanceof FedizRequest) {
                FedizRequest fedReq = (FedizRequest) fedAuthToken.getCredentials();
                try {
                    out.append(formatXML(fedReq.getResponseToken()) + "\n");
                } catch (Exception ex) {
                    out.append("Failed to parse raw token: " + ex.toString() + "\n");
                }
            } else {
                out.append("Cannot get raw token\n");
            }
        } else if (auth instanceof Pac4jAuthentication) {
            Pac4jAuthentication token = (Pac4jAuthentication) auth;
            UserProfile profile = token.getProfile();
            out.append("Recognised claims:\n");
            if (profile != null) {
                for (String claim : profile.getAttributes().keySet()) {
                    if (profile.getAttribute(claim) instanceof Iterable) {
                        for (Object value : (Iterable<?>) profile.getAttribute(claim)) {
                            out.append("    " + claim + ": " + value + "\n");
                        }
                    } else {
                        out.append("    " + claim + ": " + profile.getAttribute(claim) + "\n");
                    }
                }
            }
            out.append("\n");
            out.append("Saved profile:\n");
            out.append(token + "\n\n");
            if (profile != null) {
                if (protocol == ProtocolType.SAML && samlResponseBindingType == SamlResponseBindingType.ARTIFACT) {
                    out.append("Formatted token:\n");
                    String assertionStr;
                    String assertionFromSession = (String) session.getAttribute("saml_assertion");
                    String assertionFromProfile = (String) profile.getAttribute("saml_assertion");
                    if (assertionFromSession != null) {
                        // assertion from the session
                        assertionStr = formatXML(new String(Base64.getDecoder().decode(assertionFromSession),StandardCharsets.UTF_8));
                    } else if (assertionFromProfile != null) {
                        // assertion from the profile
                        session.setAttribute("saml_assertion", assertionFromProfile);
                        assertionStr = formatXML(new String(Base64.getDecoder().decode(assertionFromProfile),StandardCharsets.UTF_8));
                    } else {
                        // no assertion found
                        assertionStr = "<token not found>";
                    }
                    out.append("  " + assertionStr);
                } else if (protocol == ProtocolType.OIDC) {
                    out.append("Access token:\n");
                    // access token
                    BearerAccessToken accessToken = (BearerAccessToken) profile.getAttribute("access_token");
                    if (accessToken != null) {
                        insertParsedJwt(out, accessToken.getValue());
                    } else {
                        out.append("  <access token not found>");
                    }
                    // refresh token
                    out.append("\n\nRefresh token:\n");
                    // access token
                    RefreshToken refreshToken = (RefreshToken) profile.getAttribute("refresh_token");
                    if (refreshToken != null) {
                        insertParsedJwt(out, refreshToken.getValue());
                    } else {
                        out.append("  <refresh token not found>");
                    }
                    // ID token
                    out.append("\n\nID token:\n");
                    // access token
                    String idToken = (String) profile.getAttribute("id_token");
                    if (idToken != null) {
                        insertParsedJwt(out, idToken);
                    } else {
                        out.append("  <ID token not found>");
                    }
                }
            }
        } else {
            out.append("Cannot get token information from Spring Security Context\n");
        }

        return out.toString();
    }

    /**
     * Function to pretty-print an XML String passed as the argument. Doesn't escape the result for displaying in a
     * webpage though, another function must be used for that.
     *
     * @param xml A non-formatted XML String
     * @return The pretty-printed result
     */
    private String formatXML(String xml) {
        try (StringReader reader = new StringReader(xml); Writer writer = new StringWriter()) {
            Source input = new StreamSource(reader);
            StreamResult xmlOutput = new StreamResult(writer);
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute("indent-number", 2);
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(input, xmlOutput);
            String str = xmlOutput.getWriter().toString();
            str = str.replaceAll(" ", "  ");
            return str;
        } catch (IOException | TransformerException e) {
            e.printStackTrace();
            return "<Error while formatting XML>";
        }
    }

    private void insertParsedJwt(StringBuilder out, String jwt) {
        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            ObjectMapper mapper = new ObjectMapper();
            String[] chunks = jwt.split("\\.");
            String header = new String(decoder.decode(chunks[0]));
            String payload = new String(decoder.decode(chunks[1]));
            JsonNode headerMap = mapper.readTree(header);
            JsonNode payloadMap = mapper.readTree(payload);

            out.append("  Header:\n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(headerMap));
            out.append("\n  Payload:\n" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(payloadMap));
        } catch (JsonProcessingException ex) {
            ex.printStackTrace();
            out.append("  <error while parsing jwt>");
        }
    }

    @GetMapping(value = "/backchannel-logout")
    private String buildLogoutRequest(HttpServletRequest req, HttpServletResponse resp) throws MarshallingException, SecurityException, SignatureException {

        Optional<Client> potentialClient = config.getClients().findClient(CustomSAML2Client.class.getSimpleName());
        if (potentialClient.isPresent()) {
            CustomSAML2Client client = (CustomSAML2Client) potentialClient.get();

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth instanceof Pac4jAuthentication) {
                Pac4jAuthentication token = (Pac4jAuthentication) auth;
                UserProfile profile = token.getProfile();
                SessionStore bestSessionStore = FindBest.sessionStore(null, this.config, JEESessionStore.INSTANCE);
                WebContext webContext = FindBest.webContextFactory(null, this.config, JEEContextFactory.INSTANCE).newContext(req, resp);

                SAML2MessageContext msgContext = client.getContextProvider().buildContext(client, webContext, bestSessionStore);
                final SAML2LogoutRequestBuilder saml2LogoutRequestBuilder = new SAML2LogoutRequestBuilder(client.getConfiguration());
                LogoutRequest logoutRequest = saml2LogoutRequestBuilder.build(msgContext, (SAML2Profile) profile);
                msgContext.getMessageContext().setMessage(logoutRequest);
                SignatureSigningParameters signingParams = new DefaultSignatureSigningParametersProvider(client.getConfiguration()).build(msgContext.getSPSSODescriptor());
                SecurityParametersContext spContext = new SecurityParametersContext();
                spContext.setSignatureSigningParameters(signingParams);
                msgContext.getMessageContext().addSubcontext(spContext);
                // sign request if needed
                if (msgContext.getIDPSSODescriptor().getWantAuthnRequestsSigned()) {
                    SAMLMessageSecuritySupport.signMessage(msgContext.getMessageContext());
                }

                final var idpDescriptor = msgContext.getIDPSSODescriptor();
                Optional<SingleLogoutService> logoutUrlOpt = idpDescriptor.getSingleLogoutServices().stream().filter(s -> s.getBinding().contains("SOAP")).findFirst();
                if (logoutUrlOpt.isPresent()) {
                    String logoutUrl = logoutUrlOpt.get().getLocation();
                    if (sendLogoutRequest(logoutUrl, logoutRequest)) {
                        // remove the local session
                        SecurityContextHolder.clearContext();
                        Cookie cookieToDelete = new Cookie("JSESSIONID", null);
                        cookieToDelete.setMaxAge(0);
                        resp.addCookie(cookieToDelete);
                        return "index";
                    }
                }
            }
        }
        throw new RuntimeException("Logout failed");
    }

    private String toXml(LogoutRequest logoutRequest) throws MarshallingException {
        Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(logoutRequest);
        out.marshall(logoutRequest);
        Element authDOM = logoutRequest.getDOM();
        return SerializeSupport.nodeToString(authDOM, Map.of("xml-declaration", Boolean.FALSE));
    }

    public boolean sendLogoutRequest(String logoutUrl, LogoutRequest logoutRequest) {
        try {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            OkHttpClient.Builder newBuilder = new OkHttpClient.Builder();
            newBuilder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
            newBuilder.hostnameVerifier((hostname, session) -> true);

            String logoutRequestStr = SOAP11_STRUCTURE.replace("${BODY}", toXml(logoutRequest));
            System.out.println("SOAP Logout Request: " + logoutRequestStr);
            RequestBody body = RequestBody.create(logoutRequestStr, MediaType.get("text/xml; charset=utf-8"));
            Request request = new Request.Builder()
                    .url(logoutUrl)
                    .post(body)
                    .build();

            Call call = newBuilder.build().newCall(request);
            try (Response response = call.execute()) {
                if (response.code() == 200 && response.body() != null) {
                    // logout success
                    System.out.println("SOAP Logout Response: " + response.body().string());
                    return true;
                } else {
                    System.err.println("SOAP Logout Response: " + response.body().string());
                }
            }
        } catch (IOException | KeyManagementException | NoSuchAlgorithmException | MarshallingException e) {
            System.err.println("Unexpected issue while sending the SOAP logout request");
            e.printStackTrace();
        }
        return false;
    }

    TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                }

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[]{};
                }
            }
    };
}
