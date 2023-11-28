package io.cloudtrust.testclient.fediz;

import org.apache.commons.lang3.StringUtils;
import org.apache.cxf.fediz.core.config.FedizConfigurator;
import org.apache.cxf.fediz.core.config.FedizContext;
import org.apache.cxf.fediz.spring.FederationConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.web.context.ServletContextAware;

import javax.servlet.ServletContext;
import javax.xml.bind.JAXBException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

/**
 * This class replaces the FederationConfigImpl class, but allows the configuration file to be handled by a reader
 * instead of as a file. This is necessary to get a configuration file that is not directly in the file system,
 * for example one contained in a jar that needs to be accessed via the classpath.
 */
public class FederationConfigReader implements FederationConfig, ServletContextAware {
    private static final Logger LOG = LoggerFactory.getLogger(FederationConfigReader.class);

    private FedizConfigurator configurator = new FedizConfigurator();
    private ServletContext servletContext;

    private Resource configFile;
    private String contextName;
    private String relativePath;

    public Resource getConfigFile() {
        return configFile;
    }

    public void setConfigFile(Resource configFile) {
        this.configFile = configFile;
    }

    public String getMainContextName() {
        return contextName;
    }

    public void setMainContextName(String contextName) {
        this.contextName = contextName;
    }

    /**
     * Reads the federation configuration file using the FedizConfigurator class
     */
    public void init() {
        Assert.notNull(getConfigFile(), "property 'configFile' mandatory");
        try (BufferedReader br = new BufferedReader(new InputStreamReader(getConfigFile().getInputStream()))) {
            configurator.loadConfig(br);
        } catch (JAXBException | IOException e) {
            LOG.warn("Failed to parse '{}': {}", getConfigFile().getDescription(), e.getMessage());
            throw new BeanCreationException("Failed to parse '" + getConfigFile().getDescription() + "'", e);
        }
    }

    /**
     * Gets all configuration contexts, as it is possible to define a different configuration by context
     *
     * @return a list of the context configurations
     */
    @Override
    public List<FedizContext> getFedizContextList() {
        return configurator.getFedizContextList();
    }

    /**
     * Gets a context by name. The name is the value in the <contextConfig name=VALUE> attribute
     *
     * @param context the name of a context in the fediz configuration
     * @return an object representing the configuration of the fediz context
     */
    @Override
    public FedizContext getFedizContext(String context) {
        FedizContext ctx = configurator.getFedizContext(context);
        if (ctx == null) {
            String message = "Federation context '" + context + "' not found.";
            LOG.error(message);
            throw new IllegalStateException(message);
        }
        initializeRelativePath(ctx);
        return ctx;
    }

    /**
     * Initialises the relative path for a context to the value set during the initialisation of this bean
     * If none was set, tries to guess via the catalina or jetty configuration
     *
     * @param ctx The context for which to set the relative path
     */
    private void initializeRelativePath(FedizContext ctx) {
        if (relativePath != null) {
            ctx.setRelativePath(relativePath);
        }
        if (ctx.getRelativePath() == null) {
            String catalinaBase = System.getProperty("catalina.base");
            if (!StringUtils.isBlank(catalinaBase)) {
                ctx.setRelativePath(catalinaBase);
            }
        }
        if (ctx.getRelativePath() == null) {
            String jettyHome = System.getProperty("jetty.home");
            if (!StringUtils.isBlank(jettyHome)) {
                ctx.setRelativePath(jettyHome);
            }
        }
    }

    /**
     * Gets the current context from the servlet context (as the class is context aware). If this fails, can get an
     * assigned context.
     *
     * @return The current context.
     */
    @Override
    public FedizContext getFedizContext() {
        if (servletContext != null) {
            LOG.debug("Reading federation configuration for context '"+servletContext.getContextPath()+"'");
            return getFedizContext(servletContext.getContextPath());
        } else {
            Assert.notNull(contextName, "Property 'contextName' must be configured because ServletContext null");
            return getFedizContext(contextName);
        }
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    public void setRelativePath(String relativePath) {
        this.relativePath = relativePath;
    }

}
