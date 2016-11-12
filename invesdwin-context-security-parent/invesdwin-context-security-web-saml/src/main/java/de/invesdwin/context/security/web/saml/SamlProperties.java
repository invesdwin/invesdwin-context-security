package de.invesdwin.context.security.web.saml;

import java.net.URL;

import javax.annotation.concurrent.Immutable;

import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;

import de.invesdwin.context.system.properties.IProperties;
import de.invesdwin.context.system.properties.SystemProperties;
import de.invesdwin.util.lang.uri.Addresses;

@Immutable
public final class SamlProperties {

    public static final String MOUNT_PATH_SAML_LOGIN = SAMLEntryPoint.FILTER_URL;
    public static final String MOUNT_PATH_SAML_LOGIN_SUCCESS = "/saml/LoginSuccess";
    public static final String MOUNT_PATH_SAML_LOGOUT = SAMLLogoutFilter.FILTER_URL;
    public static final String MOUNT_PATH_SAML_LOGOUT_SUCCESS = "/saml/LogoutSuccess";

    public static final String ROLE_SAML_AUTHENTICATED = "SAML_AUTHENTICATED";

    public static final String ENTITY_ID;
    public static final String IDP_METADATA_RESOURCE;
    public static final URL ENTITY_BASE_URL;

    static {
        final SystemProperties systemProperties = new SystemProperties(SamlProperties.class);
        ENTITY_ID = systemProperties.getString("ENTITY_ID");
        IDP_METADATA_RESOURCE = systemProperties.getString("IDP_METADATA_RESOURCE");
        ENTITY_BASE_URL = readEntityBaseUrl(systemProperties);

        //create default password warnings
        systemProperties.getStringWithSecurityWarning("KEYSTORE_KEYPASS", IProperties.INVESDWIN_DEFAULT_PASSWORD);
        systemProperties.getStringWithSecurityWarning("KEYSTORE_STOREPASS", IProperties.INVESDWIN_DEFAULT_PASSWORD);
    }

    private SamlProperties() {}

    private static URL readEntityBaseUrl(final SystemProperties systemProperties) {
        final String key = "ENTITY_BASE_URL";
        final String expectedFormat = "Expected Format: (http|https)://<host>:<port>";
        //random port currently not supported
        final URL url = systemProperties.getURL(key, false);
        final int port = url.getPort();
        if (!Addresses.isPort(port)) {
            throw new IllegalArgumentException(systemProperties.getErrorMessage(key, url, null,
                    "Port [" + port + "] is incorrect (needs to be >0). " + expectedFormat));
        }
        return url;
    }

}
