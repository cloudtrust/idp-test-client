# IdP test client

This is an implementation of a simple Service Provider(SP) for testing single sign-on (SSO) and single logout (SLO) for
the following protocols:

* [WS-Federation](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html) (WS-Fed)
* SAML
* OIDC

For this purpose, it uses the following software stack:

1. [Spring Boot](https://projects.spring.io/spring-boot/)
1. [Spring Security](https://projects.spring.io/spring-security/)
1. [Apache CXF Fediz](http://cxf.apache.org/fediz.html) for WS-Fed, and [PAC4J](http://www.pac4j.org/) for SAML and OIDC

It's purpose is to provide a resource to test an IdP's implementation of those protocols, or to test the setup of
such an IdP. This client has the following restrictions:

* It is only used for 
[passive requestors](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html#_Toc223175002) 
(i.e browsers).
* WS-Fed doesn't specify the token format, leaving the choice free to the implementation. This test client currently
 supports SAML 1.1 and SAML 2 tokens.
* TODO: NOTE RESTRICTIONS FOR SAML AND OIDC

This test client was initially developed to be used to test the 
[WS-Fed module for Keycloak](https://github.com/cloudtrust/keycloak-wsfed) and was later expanded to include OIDC and 
SAML. Therefore, all configuration examples use Keycloak as reference. However, this test client should work with any 
implementation of the supported protocols.

## How to build

Simply package with maven: `mvn clean package`. The result is an executable jar containing all necessary dependencies.

## How to configure

The configuration uses the following files: a **keystore**, a **fediz configuration file**, a **SAML IDPSSODescriptor 
xml file**, and an **application properties file**.

The **keystore** is used to store the public key of the IdP, as well as the public-private key pair of the client.
A local keystore, `localstore.jks` is provided, which is used both for the WS-Fed and SAML protocols. It is possible to 
specify other keystores to use (up to two, for WS-Fed and SAML) by modifying the references in the `fediz_config.xml`
and `application.properties`.

The **fediz configuration file** contains the configuration of the client and of the IdP. The description of the
configuration file is provided [here](http://cxf.apache.org/fediz-configuration.html), and the provided 
`fediz_configuration` file is the reference configuration for this test client. It is commented to describe each element
of the configuration.

The **SAML IDPSSODescriptor xml file** contains the configuration of the IdP for the SAML client. For Keycloak, this can
be automatically generated from the configuration page of the SAML client, on the installation tab.

The **application properties** file is used for the general application configuration, the configuration for the use
of the SAML protocol, and for the use of the OIDC protocol. In this file we also specify which of the three protocols
(WS-Fed, SAMl or OIDC) will be used to secure the test client. It is commented to describe each element of the 
configuration.

All configuration values can be set before building, or after building by editing the files from within the resulting 
jar. It is also possible set other files and values with command line options (see below). 

The application can only use a single protocol to protect its resource at run time, but of course it is possible to run
the application multiple time to simulate multiple test clients. The protocol is selected using the 
`connection.protocol` value, set in the **application.properties file**. By default it is set to WS-Fed.

Note that the normally the Fediz library provides configuration metadata for the IdP for the WS-Fed protocol at 
`http[s]://<host>:<port>/<context>/FederationMetadata/2007-06/FederationMetadata.xml`, or by default in our case: 
`http://localhost:7000/FederationMetadata/2007-06/FederationMetadata.xml`, but currently this is not working.

## How to use

### Command line options

After building, run the resulting jar with `java -jar IdPTestClient.jar`. 

Any configuration element of the **application.properties** can be modified at runtime by appending a value with the 
format `--<PROPERTY.NAME>=<VALUE>`. For example, the port can be set to 9000 `--server.port=9000`.

As the paths to all the other configuration files are specified in the **application.properties**, meaning that the 
application can be fully configured even with a built jar by specifying the properties and properties files when running
the application. For example, the path to a fediz configuration file can be specified by adding 
`--fediz.configFilePath=file://</PATH/TO/FILE>`.

### Using the application

After running, go to the address being listened to (by default `http://localhost:7000`). The first link on the page will 
redirect to `http://localhost:7000/tokenInformation`, which is protected by IdP access. Once accessed, this page 
contains information on the token provided by the IdP for verification purposes.

It is also possible to to a single logout by using the second link on initial page, which by default is at 
`http://localhost:7000/singleLogout`. For WS-Fed and SAML, this leads to a logout page after the automatic logout, but 
currently for OIDC it leads back to the base page.
