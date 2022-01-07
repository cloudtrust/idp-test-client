package io.cloudtrust.testclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import io.cloudtrust.testclient.config.ProtocolType;
import io.cloudtrust.testclient.saml.SamlResponseBindingType;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.springframework.security.authentication.Pac4jAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
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
import java.security.Principal;
import java.util.Base64;

@Controller
public class TokenInfoController {

    @Value("${connection.protocol:WSFED}")
    private ProtocolType protocol;
    @Value("${saml.responseBindingType:ARTIFACT}")
    private SamlResponseBindingType samlResponseBindingType;

    @GetMapping(value = "/")
    public String home(Model model, HttpServletRequest req) {
        model.addAttribute("principal", req.getUserPrincipal());
        return "index";
    }

    @GetMapping(value = "/secured")
    public String authenticated(Model model, HttpServletRequest req) {
        model.addAttribute("principal", req.getUserPrincipal());
        model.addAttribute("tokenInfo", buildTokenInfo(req.getUserPrincipal()));
        return "index";
    }

    private String buildTokenInfo(Principal p) {
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
                    out.append("Formatted token (obtained through artifact binding):\n");
                    if (profile.getAttribute("saml_assertion") != null) {
                        out.append("  " + formatXML((String) profile.getAttribute("saml_assertion")));
                    } else {
                        out.append("  <token not found>");
                    }
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
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
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
}
