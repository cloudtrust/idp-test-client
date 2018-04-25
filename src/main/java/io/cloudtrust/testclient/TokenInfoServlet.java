package io.cloudtrust.testclient;

import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.cxf.fediz.core.Claim;
import org.apache.cxf.fediz.core.processor.FedizRequest;
import org.apache.cxf.fediz.spring.authentication.FederationAuthenticationToken;
import org.pac4j.springframework.security.authentication.Pac4jAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.security.Principal;

/**
 * This class implements a servlet that displays the information contained in the token provided by the IdP.
 *
 * Upon a get, it displays the user id used by the protocol, the claims that are recognised, and the raw token/profile
 */

@WebServlet(
        name = "TokenInfoServlet",
        displayName = "Token Information",
        description = "Gives the details of the token received",
        urlPatterns = {"/tokenInformation"}
)
public class TokenInfoServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();

        out.println("<html>" +
                "<head><title>Token Information page</title></head>" +
                "<body>" +
                "<h1>Login successful, welcome</h1>");

        Principal p = req.getUserPrincipal();
        if (p != null) {
            out.println("<h2>User</h2>" +
                    "Principal: " + p.getName());
        } else {
            out.println("<p>Missing user principal information</p>");
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof FederationAuthenticationToken) {
            FederationAuthenticationToken fedAuthToken = (FederationAuthenticationToken)auth;
            out.println("<h2>Recognised claims</h2>" +
                    "<ul>");
            for (Claim claim : fedAuthToken.getClaims()){
                if (claim.getValue() instanceof Iterable) {
                    for (Object value : (Iterable)claim.getValue()) {
                        out.println("<li>" + claim.getClaimType() + ": " + value + "</li>");
                    }
                } else {
                    out.println("<li>" + claim.getClaimType()+ ": " + claim.getValue() + "</li>");
                }
            }
            out.println("</ul>");

            out.println("<h2>Raw token</h2>");
            if (fedAuthToken.getCredentials() instanceof FedizRequest) {
                FedizRequest fedReq = (FedizRequest)fedAuthToken.getCredentials();
                try {
                    out.println("<p><pre>" + StringEscapeUtils.escapeXml10(formatXML(fedReq.getResponseToken()))+ "</pre></p>");
                } catch (Exception ex) {
                    out.println("Failed to parse raw token: " + ex.toString()  +"");
                }
            } else {
                out.println("Cannot get raw token");
            }
        } else if (auth instanceof Pac4jAuthentication){
            Pac4jAuthentication token = (Pac4jAuthentication) auth;
            out.println("<h2>Recognised claims</h2>" +
                    "<ul>");
            if (token.getProfile() != null) {
                for (String claim : token.getProfile().getAttributes().keySet()) {
                    if (token.getProfile().getAttribute(claim) instanceof Iterable) {
                        for (Object value : (Iterable)token.getProfile().getAttribute(claim)){
                            out.println("<li>" + claim + ": " + value + "</li>");
                        }
                    } else {
                        out.println("<li>" + claim + ": " + token.getProfile().getAttribute(claim) + "</li>");
                    }
                }
            }
            out.println("</ul>");
            out.println("<h2>Saved profile</h2>");
            out.println("<p>" + token + "</p>");
        } else {
            out.println("<p>Cannot get token information from Spring Security Context</p>");
        }

        out.println("<p><a href=\"/\">Return</a></p>" +
                "</body>" +
                "</html>");
        out.close();
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
            return xmlOutput.getWriter().toString();
        }
    }
}
