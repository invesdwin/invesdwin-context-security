package org.apache.commons.crypto.random;

import javax.annotation.concurrent.Immutable;

/**
 * We have to avoid JavaCryptoRandomGenerator: https://issues.apache.org/jira/projects/CRYPTO/issues/CRYPTO-160
 */
@Immutable
public final class JavaCryptoRandomDetector {

    private static boolean javaCryptoRandomDetected = false;

    private JavaCryptoRandomDetector() {
    }

    public static boolean isJavaCryptoRandomDetected() {
        return javaCryptoRandomDetected;
    }

    public static boolean isJavaCryptoRandom(final CryptoRandom cryptoRandom) {
        final boolean javaCryptoRandom = cryptoRandom instanceof JavaCryptoRandom;
        if (javaCryptoRandom) {
            javaCryptoRandomDetected = true;
        }
        return javaCryptoRandom;
    }

}
