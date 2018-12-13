package io.cloudtrust.testclient;

import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.text.StringEscapeUtils;
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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.transform.*;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.security.Principal;

@Controller
public class TokenInfoController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String home(Model model, HttpServletRequest req) {
        model.addAttribute("principal", req.getUserPrincipal());
        return "index";
    }

    @RequestMapping(value = "/tokenInformation", method = RequestMethod.GET)
    public String tokenInfo(Model model, HttpServletRequest req) {
        Principal p = req.getUserPrincipal();
        String username;
        if (p != null) {
            username = p.getName();
        } else {
            username = "<missing user principal information>";
        }
        model.addAttribute("principal", req.getUserPrincipal());
        return "index";
    }

//    @RequestMapping(value = "/logout", method = RequestMethod.GET)
//    public String logout(Model model, HttpServletRequest req) {
//        HttpSession session = req.getSession(false);
//        if (session != null) {
//            session.invalidate();
//        }
//        return "index";
//    }
}
