package de.invesdwin.context.security.web.cas;

import java.net.URI;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.system.properties.SystemProperties;

@Immutable
public final class CasProperties {

    public static final String ROLE_CAS_AUTHENTICATED = "CAS_AUTHENTICATED";
    public static final URI CAS_SERVICE_URI;

    public static final String MOUNT_PATH_CAS_LOGIN = "/cas/login";
    public static final String MOUNT_PATH_CAS_LOGIN_SUCCESS = "/cas/LoginSuccess";
    public static final String MOUNT_PATH_CAS_LOGOUT = "/cas/logout";
    public static final String MOUNT_PATH_CAS_LOGOUT_SUCCESS = "/cas/LogoutSuccess";

    static {
        final SystemProperties systemProperties = new SystemProperties(CasProperties.class);
        CAS_SERVICE_URI = systemProperties.getURI("CAS_SERVICE_URI", false);
    }

    private CasProperties() {}

}
