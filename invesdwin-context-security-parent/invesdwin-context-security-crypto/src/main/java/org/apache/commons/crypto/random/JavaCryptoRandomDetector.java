package org.apache.commons.crypto.random;

import java.security.GeneralSecurityException;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorAdapter;
import de.invesdwin.context.security.crypto.random.CommonsCryptoRandomGeneratorAdapter;
import de.invesdwin.context.system.properties.SystemProperties;

/**
 * We have to avoid JavaCryptoRandomGenerator: https://issues.apache.org/jira/projects/CRYPTO/issues/CRYPTO-160
 */
@Immutable
public final class JavaCryptoRandomDetector {

    private static boolean javaCryptoRandomDetected = false;

    private JavaCryptoRandomDetector() {
    }

    private static boolean isJavaCryptoRandomDetected() {
        return javaCryptoRandomDetected;
    }

    private static boolean isJavaCryptoRandom(final CryptoRandom cryptoRandom) {
        final boolean javaCryptoRandom = cryptoRandom instanceof JavaCryptoRandom;
        if (javaCryptoRandom) {
            javaCryptoRandomDetected = true;
        }
        return javaCryptoRandom;
    }

    public static CryptoRandomGenerator newCryptoRandom() {
        try {
            if (JavaCryptoRandomDetector.isJavaCryptoRandomDetected()) {
                return newFallbackCryptoRandom();
            }
            final org.apache.commons.crypto.random.CryptoRandom cryptoRandom = CryptoRandomFactory
                    .getCryptoRandom(SystemProperties.SYSTEM_PROPERTIES);
            if (JavaCryptoRandomDetector.isJavaCryptoRandom(cryptoRandom)) {
                return newFallbackCryptoRandom();
            }
            return new CommonsCryptoRandomGeneratorAdapter(cryptoRandom);
        } catch (final GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static CryptoRandomGeneratorAdapter newFallbackCryptoRandom() {
        return new CryptoRandomGeneratorAdapter(new java.security.SecureRandom());
    }

}
