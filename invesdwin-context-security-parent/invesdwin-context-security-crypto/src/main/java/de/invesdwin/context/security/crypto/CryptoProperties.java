package de.invesdwin.context.security.crypto;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.system.properties.IProperties;
import de.invesdwin.context.system.properties.SystemProperties;
import de.invesdwin.util.time.duration.Duration;

@Immutable
public final class CryptoProperties {

    public static final byte[] DEFAULT_PEPPER;
    public static final Duration RESEED_INTERVAL;

    static {
        final SystemProperties systemProperties = new SystemProperties(CryptoProperties.class);
        DEFAULT_PEPPER = systemProperties
                .getStringWithSecurityWarning("DEFAULT_PEPPER", IProperties.INVESDWIN_DEFAULT_PASSWORD)
                .getBytes();
        RESEED_INTERVAL = systemProperties.getDuration("RESEED_INTERVAL");
    }

    private CryptoProperties() {}

}
