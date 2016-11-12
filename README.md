# invesdwin-context-security
 invesdwin-context modules that provide security features

## Maven

Releases and snapshots are deployed to this maven repository:
```
http://invesdwin.de/artifactory/invesdwin-oss
```

Dependency declaration:
```xml
<dependency>
	<groupId>de.invesdwin</groupId>
	<artifactId>invesdwin-context-integration</artifactId>
	<version>1.0.0-SNAPSHOT</version>
</dependency>
```
## Security Modules

The `invesdwin-context-security` module configures the [spring-security](http://projects.spring.io/spring-security/) annotations for method level authorization. Other security modules reference this module to provide actual authorization rules to be used. Please note that the `DefaultRolePrefixRemover` changes spring-security configurations so that the `ROLE_` prefix can be ommitted (which can be unintuitive when it has or has not to be used). So to make things easier, just put role names as they are (coming from a database, ldap, manual configuration and so on) inside your autorization expressions, without adding any prefixes. The Kerberos module provides some utilities to generate krb5.conf and keytab files while also defining some Kerberos client configuration. See the [invesdwin-context-persistence](https://github.com/subes/invesdwin-context-persistence) project for more information on the Kerberos integration and also for an embedded LDAP+Kerberos server module.

## LDAP Modules

These modules provide integration for LDAP clients using [spring-ldap](http://projects.spring.io/spring-ldap/). The following tools are available:

- **ALdapDao**: this is a DAO implementation for LDAP similarly to the ADao available for JPA in [invesdwin-context-persistence-jpa](https://github.com/subes/invesdwin-context-persistence/). Again just extend it for each Entry (this is an Entity in LDAP speak) and write your queries in there. `@Transactional` and QueryDSL support is provided out the box by this module. Configuration is done by the following properties:
```properties
de.invesdwin.context.persistence.ldap.LdapProperties.LDAP_CONTEXT_URI=ldap://localhost:10389
de.invesdwin.context.persistence.ldap.LdapProperties.LDAP_CONTEXT_BASE=dc=invesdwin,dc=de
de.invesdwin.context.persistence.ldap.LdapProperties.LDAP_CONTEXT_USERNAME=uid=admin,ou=system
de.invesdwin.context.persistence.ldap.LdapProperties.LDAP_CONTEXT_PASSWORD=invesdwin
```
- **@DirectoryServerTest**: use this annotation in your unit tests to run an embedded [ApacheDS](http://directory.apache.org/apacheds/) LDAP and Kerberos server. The `DirectoryServer` bean can be injected anywhere and you can load your own LDIF files via it. Alternatively just insert some Entries via the ALdapDao facility. You can also browse the directory with the [Apache Directory Studio](http://directory.apache.org/studio/) client application. To run the embedded directory server inside your production distribution, simply make sure to call  `DirectoryServerContextLocation.activate()` in your Main class before the application bootstrap is started. The integrated Kerberos server follows the configuration provided in the `invesdwin-context-security-kerberos` module:
```properties
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_SERVER_URI=localhost:6088
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_PRIMARY_REALM=INVESDWIN.DE
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_DEBUG=true
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_SERVICE_PRINCIPAL=HTTP/localhost@INVESDWIN.DE
#not needed when KEYTAB is specified; if specified, a default keytab will be generated with information given here
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_SERVICE_PASSPHRASE=invesdwin

# you can give a path to a keytab resoure here alternatively to setting the passphrase; being empty, a default keytab will be generated with principal/passphrase given
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_KEYTAB_RESOURCE=
# instead of generating a new krb5conf according to settings provided here, you can specify a resource to one here; being empty, a default krb5.conf will be generated with the above information
de.invesdwin.context.security.kerberos.KerberosProperties.KERBEROS_KRB5CONF_RESOURCE=
```
