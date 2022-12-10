# invesdwin-context-security
This project provides security modules for the [invesdwin-context](https://github.com/subes/invesdwin-context) module system.

## Maven

Releases and snapshots are deployed to this maven repository:
```
https://invesdwin.de/repo/invesdwin-oss-remote/
```

Dependency declaration:
```xml
<dependency>
	<groupId>de.invesdwin</groupId>
	<artifactId>invesdwin-context-security-web</artifactId>
	<version>1.0.2</version><!---project.version.invesdwin-context-security-parent-->
</dependency>
```
## Security Modules

The `invesdwin-context-security` module configures the [spring-security](http://projects.spring.io/spring-security/) annotations for method level authorization. Other security modules reference this module to provide actual authorization rules to be used. Please note that the `DefaultRolePrefixRemover` changes spring-security configurations so that the `ROLE_` prefix can be ommitted (which can be unintuitive when it has or has not to be used). So to make things easier, just put role names as they are (coming from a database, ldap, manual configuration and so on) inside your autorization expressions, without adding any prefixes.

### Crypto Module

The `invesdwin-context-security-crypto` contains implementations for common cryptographic algorithms. We use JCA so you can plug in your custom (maybe native) security provider. We also have an integration for [commons-crypto](https://commons.apache.org/proper/commons-crypto/) (which does not use JCA).

- **IEncryptionFactory**: this allows to encrypt/decrypt buffers and streams of data. We use this simplified abstraction to declaratively secure communication channels in [invesdwin-context-integration-channel](https://github.com/invesdwin/invesdwin-context-integration#synchronous-channels) with respect to performance (following zero-allocation and zero-copy principles where possible without compromising security).
	-  `SymmetricEncryptionFactory` is used for AES and other symmetric algorithms.
	-  `AsymmetricEncryptionFactory` is used for RSA and other asymmetric algorithms based on public/private key pairs.
	-  `VerifiedEncryptionFactory` allows to combine an `IEncryptionFactory` with an `IVerificationFactory` to use AES with hashes (e.g. HMAC) or signatures (RSA, DSA, ECDSA, EDDSA).
	-  `HybridEncryptionFactory` allows to use an exchanged public/private key (with RSA) to exchange a session specific symmetric key (for AES). Just discard and create a new session to initiate a key rollover.
-  **IVerificationFactory**: this allows to add a checksum (error detection using CRC, Adler, XXHash), digest (adds integrity using SHA, SHAKE, ...), mac (adds authentication using HMAC, GMAC, ...) or signature (adds non-repudiation using RSA, DSA, ECDSA, EDDSA) of buffers or streams of data.
-  **IDerivedKeyProvider**: can be used to derive deterministic keys from pre shared information (e.g. a password) of from key exchange procedure (random hashes that were securely communicated). Or it can be used to derive secure keys from entirely random data. It can either use HKDF or an `IPasswordHasher` for the derivation. You can generate typical symmetric keys for encryption, verification, signatures). With `SelfSignedCertGenerator` you can even create self signed certificates for SSL/TLS (based on a derived or generated public/private key pair from IDerivedKeyProvider).
-  **IPasswordHasher**: can be used to hash plain text passwords for secure storage (Bcrypt, PBKDF2, Scrypt, Argon2). Pick the paramters so that time and memory is spent for the generation to make cracking the password using GPU or TPU sufficiently hard. This can be optimized automatically using APasswordHasherBenchmark to e.g. target 2 seconds of effort on your hardware. It makes sense to use Argon2 as the default implementation, because it also uses configurable memory effort to make it harder to crack on highly parallel hardware and there is a native binding which allows to compute iterations faster while using off-heap memory. Always keep in mind to use salt (random bytes per password) and pepper (a pre shared secret) when creating your hashes. Use our `NativeArgon2PasswordEncoder` implementation for the [spring-security-crypto](https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/crypto.html) `PasswordEncoder` interface to store and manage passwords in a database. It saves the salt, algorithm and its parameters alongside the password and provides automations to upgrade existing hashes to more secure parameters ot algorithms. `IArgon2PasswordHasher.getDefault()` is used to fallback to a pure Java implementation if the native Argon2 implementation can not be loaded.
- **CryptoRandomGenerators**: pools, threadlocals, adapters and wrappers for SecureRandom implementations that get reseeded automatically in intervals (configurable with the system property `de.invesdwin.context.security.crypto.CryptoProperties.RESEED_INTERVAL=1 MINUTES`). `StrongRandomGenerators` forces a slower but maybe more secure random generator (DRBG instead of SHA1PRNG). Though be aware that in reality both random generators might be considered secure and that using an algorithm that needs to wait for entropy in the operating system can quickly become unbearably slow (some native or blocking implementations). So if you must, use it only to generate keys for long term storage, otherwise switch to a faster secure random generator that uses a cryprographically secure hashing function. Also prefer to use [PseudoRandomGenerators](https://github.com/invesdwin/invesdwin-util/blob/master/README.md#pseudorandomgenerators) where security is not a concern. Here some benchmarks (2022, Core i9-9900K with SSD, Java 17):
```
Reuse instance:
PseudoRandomGenerator (XoShiro256+)		Records: 1493363.24/ms	=> 638.15 times faster (insecure)
SHA1PRNG (SecureRandom) 			Records:    6236.09/ms 	=> 1.67 times faster (CryptoRandomGenerator)
CryptoRandom (NativePRNG) 			Records:    2346.06/ms	=> 0.4% faster
ThreadLocalCryptoRandom (NativePRNG) 		Records:    2343.89/ms	=> 0.3% faster
jdkDefault (NativePRNG) 			Records:    2336.50/ms	=> Baseline
jdkStrong (Blocking) 				Records:    2297.08/ms	=> 1.7% slower
CryptoRandomGeneratorObjectPool 		Records:    1674.06/ms	=> 28.4% slower
DRBG (Hash_DRBG,SHA-256,128,reseed_only)	Records:     744.17/ms	=> 68.2% slower (StrongRandomGenerator)
CommonsCryptoRandom (OpenSslCryptoRandom) 	Records:     306.47/ms	=> 86.9% slower
Conscrypt (OpenSSLRandom) 			Records:      80.12/ms	=> 96.6% slower
NIST800-90A/AES-CTR-256 (SPI) 			Records:      52.10/ms	=> 97.8% slower
BC (Default) 					Records:      47.48/ms	=> 98.0% slower

Don't reuse instance:
PseudoRandomGenerator (XoShiro256+)		Records:   43115.07/ms 	=> 401.87 times faster (insecure)
ThreadLocalCryptoRandom (NativePRNG)		Records:    2247.64/ms	=> 20 times faster
CryptoRandomGeneratorObjectPool			Records:    1680.83/ms	=> 14.7 times faster
CryptoRandom (NativePRNG)			Records:     191.83/ms	=> 79.2% faster
DRBG (Hash_DRBG,SHA-256,128,reseed_only)	Records:     111.24/ms	=> 3.9% faster (StrongRandomGenerator)
jdkDefault (NativePRNG)				Records:     107.02/ms	=> Baseline
SHA1PRNG (SecureRandom)				Records:      98.95/ms	=> 7.5% slower (CryptoRandomGenerator)
CommonsCryptoRandom (OpenSslCryptoRandom)	Records:      93.49/ms	=> 12.6% slower
jdkStrong (Blocking)				Records:      91.43/ms	=> 14.6% slower
Conscrypt (OpenSSLRandom)			Records:      43.31/ms	=> 59.5% slower
NIST800-90A/AES-CTR-256 (SPI)			Records:      39.97/ms	=> 62.6% slower
BC (Default)					Records:      30.71/ms	=> 71.3% slower
```

### Kerberos Modules

The `invesdwin-context-security-kerberos` module provides some utilities to generate krb5.conf and keytab files while also defining some Kerberos client configuration. The following **LDAP Modules** section goes deeper into the Kerberos integration and also shows an embedded LDAP+Kerberos server module. The client configuration uses the same properties as the server configuration explained there.

### LDAP Modules

These modules provide integration for LDAP clients using [spring-ldap](http://projects.spring.io/spring-ldap/). The following tools are available:

- **ALdapDao**: this is a DAO implementation for LDAP similarly to the ADao available for JPA in [invesdwin-context-persistence-jpa](https://github.com/subes/invesdwin-context-persistence/). Just extend it for each Entry (this is an Entity in LDAP speak) and write your queries in there. `@Transactional` and QueryDSL support is provided out of the box by this module. Configuration is done by the following properties:
```properties
de.invesdwin.context.security.ldap.LdapProperties.LDAP_CONTEXT_URI=ldap://localhost:10389
de.invesdwin.context.security.ldap.LdapProperties.LDAP_CONTEXT_BASE=dc=invesdwin,dc=de
de.invesdwin.context.security.ldap.LdapProperties.LDAP_CONTEXT_USERNAME=uid=admin,ou=system
de.invesdwin.context.security.ldap.LdapProperties.LDAP_CONTEXT_PASSWORD=invesdwin
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
### Web Modules

The `invesdwin-context-security-web-*` modules provide integration of security solutions for web applications:

- **Kerberos**: the `invesdwin-context-security-web-kerberos` module allows your web application to use single sign on via [SPNEGO](https://en.wikipedia.org/wiki/SPNEGO) over Kerberos. It reuses the existing configuration of the `invesdwin-context-security-kerberos` module and just adds the spring context configuration to make use of it in the servlet context. This module was successfully tested against [OpenLDAP](http://www.openldap.org/) and ApacheDS (which is available as an embedded server as explained above).
- **SAML**: the `invesdwin-context-security-web-saml` module provides support for single sign on via [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language). This module was successfully tested against the [SSOCircle](http://www.ssocircle.com) server. The following configuration options are available:
```properties
de.invesdwin.context.security.web.saml.SamlProperties.ENTITY_ID=urn:de:invesdwin:serviceprovider
# you can specify web paths (http: or https: prefix) filesystem paths (no prefix) or classpath paths (classpath: prefix)
de.invesdwin.context.security.web.saml.SamlProperties.IDP_METADATA_RESOURCE=http://idp.ssocircle.com/idp-meta.xml
# you should change this to the external url when using a reverse proxy configuration
de.invesdwin.context.security.web.saml.SamlProperties.ENTITY_BASE_URL=${de.invesdwin.context.integration.IntegrationProperties.WEBSERVER_BIND_URI}
de.invesdwin.context.security.web.saml.SamlProperties.KEYSTORE_RESOURCE=classpath:/META-INF/SamlKeystore.jks
de.invesdwin.context.security.web.saml.SamlProperties.KEYSTORE_ALIAS=invesdwin
de.invesdwin.context.security.web.saml.SamlProperties.KEYSTORE_KEYPASS=invesdwin
de.invesdwin.context.security.web.saml.SamlProperties.KEYSTORE_STOREPASS=${de.invesdwin.context.security.web.saml.SamlProperties.KEYSTORE_KEYPASS}
```
- **CAS**: the `invesdwin-context-security-web-cas` module provides support for single sign on via [CAS](https://en.wikipedia.org/wiki/Central_Authentication_Service). This module is currently in an experimental state and is not yet fully tested.

Further modules for e.g. OpenID or OAuth might come in the future to allow single sign on with Google or Facebook. If you want to use single sign on with [Active Directory](https://en.wikipedia.org/wiki/Active_Directory) you can already use Kerberos directly or SAML with the [Active Directory Federation Services](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services) using the appropriate modules above.

See the code of the [invesdwin-context-integration-ws](https://github.com/subes/invesdwin-context-integration/blob/master/invesdwin-context-integration-parent/invesdwin-context-integration-ws/src/main/java/META-INF/ctx.integration.ws.xml) module to see a simpler example of securing your web applications via the [spring-security namespace configuration](http://docs.spring.io/spring-security/site/docs/current/reference/html/ns-config.html#ns-minimal).

For examples of using the single sign on modules with wicket, you can have a look at the `invesdwin-context-client-wicket-examples` module of [invesdwin-context-client](https://github.com/subes/invesdwin-context-client). The project also provides wicket integration modules for some of the technologies discussed here.

## Support

If you need further assistance or have some ideas for improvements and don't want to create an issue here on github, feel free to start a discussion in our [invesdwin-platform](https://groups.google.com/forum/#!forum/invesdwin-platform) mailing list.
