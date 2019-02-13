package io.cloudtrust.testclient;

import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.pac4j.springframework.security.authentication.Pac4jAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.security.Principal;

@Controller
public class TokenInfoController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String home(Model model, HttpServletRequest req) {
        model.addAttribute("principal", req.getUserPrincipal());
        return "index";
    }

    @RequestMapping(value = "/secured", method = RequestMethod.GET)
    public String authenticated(Model model, HttpServletRequest req) {
        Principal p = req.getUserPrincipal();
        model.addAttribute("principal", req.getUserPrincipal());
        model.addAttribute("tokenInfo", buildTokenInfo(req.getUserPrincipal()));
        return "index";
    }

    private String buildTokenInfo(Principal p) {
        StringBuffer out = new StringBuffer();

        if (p != null) {
            out.append("User\n" +
                    "Principal: " + p.getName() + "\n");
        } else {
            out.append("Missing user principal information\n");
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof FederationAuthenticationToken) {
            FederationAuthenticationToken fedAuthToken = (FederationAuthenticationToken)auth;
            out.append("Recognised claims:\n");
            for (Claim claim : fedAuthToken.getClaims()){
                if (claim.getValue() instanceof Iterable) {
                    for (Object value : (Iterable)claim.getValue()) {
                        out.append("    " + claim.getClaimType() + ": " + value + "\n");
                    }
                } else {
                    out.append("    " + claim.getClaimType()+ ": " + claim.getValue() + "\n");
                }
            }
            out.append("\n");

            out.append("Raw token:\n");
            if (fedAuthToken.getCredentials() instanceof FedizRequest) {
                FedizRequest fedReq = (FedizRequest)fedAuthToken.getCredentials();
                try {
                    out.append(formatXML(fedReq.getResponseToken())+ "\n");
                } catch (Exception ex) {
                    out.append("Failed to parse raw token: " + ex.toString() + "\n");
                }
            } else {
                out.append("Cannot get raw token\n");
            }
        } else if (auth instanceof Pac4jAuthentication){
            Pac4jAuthentication token = (Pac4jAuthentication) auth;
            out.append("Recognised claims:\n");
            if (token.getProfile() != null) {
                for (String claim : token.getProfile().getAttributes().keySet()) {
                    if (token.getProfile().getAttribute(claim) instanceof Iterable) {
                        for (Object value : (Iterable)token.getProfile().getAttribute(claim)){
                            out.append("    " + claim + ": " + value + "\n");
                        }
                    } else {
                        out.append("    " + claim + ": " + token.getProfile().getAttribute(claim) + "\n");
                    }
                }
            }
            out.append("\n");
            out.append("Saved profile:\n");
            out.append(token + "\n");
        } else {
            out.append("Cannot get token information from Spring Security Context\n");
        }

        return out.toString();
    }

    /**
     * Function to pretty-print an XML String passed as the argument. Doesn't escape the result for displaying in a
     * webpage though, another function must be used for that.
     * @param xml A non-formatted XML String
     * @return The pretty-printed result
     * @throws IOException Thrown if there's a problem creating the reader or writer
     * @throws TransformerException Thrown if there's a problem parsing the XML
     */
    private String formatXML(String xml) throws IOException, TransformerException {
        try(StringReader reader = new StringReader(xml); Writer writer = new StringWriter()) {
            Source input = new StreamSource(reader);
            StreamResult xmlOutput = new StreamResult(writer);
            TransformerFactory transformerFactory = new TransformerFactoryImpl();
            transformerFactory.setAttribute("indent-number", 2);
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(input, xmlOutput);
            String str = xmlOutput.getWriter().toString();
            str = str.replaceAll(" ", "  ");
            return str;
        }
    }
}
