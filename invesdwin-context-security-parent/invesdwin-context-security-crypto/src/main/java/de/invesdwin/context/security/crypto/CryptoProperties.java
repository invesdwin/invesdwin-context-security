package de.invesdwin.context.security.crypto;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.system.properties.IProperties;
import de.invesdwin.context.system.properties.SystemProperties;

@Immutable
public final class CryptoProperties {

    public static final byte[] DEFAULT_PEPPER;

    static {
        final SystemProperties systemProperties = new SystemProperties(CryptoProperties.class);
        DEFAULT_PEPPER = systemProperties
                .getStringWithSecurityWarning("DEFAULT_PEPPER", IProperties.INVESDWIN_DEFAULT_PASSWORD)
                .getBytes();
    }

    private CryptoProperties() {
    }

}
