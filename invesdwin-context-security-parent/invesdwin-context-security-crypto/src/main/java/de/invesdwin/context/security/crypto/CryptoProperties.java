package de.invesdwin.context.security.crypto;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.system.properties.IProperties;
import de.invesdwin.context.system.properties.SystemProperties;
import de.invesdwin.util.time.duration.Duration;

@Immutable
public final class CryptoProperties {

    /**
     * StartTLS is susceptible to Man-in-the-Middle-Attacks: https://de.wikipedia.org/wiki/STARTTLS
     */
    public static final boolean DEFAULT_START_TLS_ENABLED = false;

    public static final String DEFAULT_PEPPER_STR;
    public static final byte[] DEFAULT_PEPPER;
    public static final Duration RESEED_INTERVAL;

    static {
        final SystemProperties systemProperties = new SystemProperties(CryptoProperties.class);
        DEFAULT_PEPPER_STR = systemProperties.getStringWithSecurityWarning("DEFAULT_PEPPER",
                IProperties.INVESDWIN_DEFAULT_PASSWORD);
        DEFAULT_PEPPER = DEFAULT_PEPPER_STR.getBytes();
        RESEED_INTERVAL = systemProperties.getDuration("RESEED_INTERVAL");
    }

    private CryptoProperties() {}

}
