package de.invesdwin.context.security.crypto.random;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.Immutable;

import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.apache.commons.crypto.random.JavaCryptoRandomDetector;

import de.invesdwin.context.system.properties.SystemProperties;

@Immutable
public final class CryptoRandomGenerators {

    /**
     * https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/src/com/amazon/corretto/crypto/provider/AmazonCorrettoCryptoProvider.java
     */
    private static final String LIB_CRYPTO_RNG = "LibCryptoRng";
    private static final String SHA1PRNG = "SHA1PRNG";
    private static boolean tryLibCryptoRng = true;

    private CryptoRandomGenerators() {
    }

    public static CryptoRandomGenerator newCryptoRandom(final byte[] seed) {
        try {
            //we need a software based implementation to be able to set a seed
            final java.security.SecureRandom secureRandom = java.security.SecureRandom.getInstance(SHA1PRNG);
            secureRandom.setSeed(seed);
            return new CryptoRandomGenerator(secureRandom);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static CryptoRandomGenerator newCryptoRandom(final long seed) {
        try {
            //we need a software based implementation to be able to set a seed
            final java.security.SecureRandom secureRandom = java.security.SecureRandom.getInstance(SHA1PRNG);
            secureRandom.setSeed(seed);
            return new CryptoRandomGenerator(secureRandom);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static CryptoRandomGenerator newCryptoRandom() {
        try {
            //prefer amazon corretto when possible
            if (tryLibCryptoRng) {
                try {
                    return new CryptoRandomGenerator(java.security.SecureRandom.getInstance(LIB_CRYPTO_RNG));
                } catch (final NoSuchAlgorithmException e) {
                    tryLibCryptoRng = false;
                }
            }
            if (JavaCryptoRandomDetector.isJavaCryptoRandomDetected()) {
                return newFallbackCryptoRandom();
            }
            final org.apache.commons.crypto.random.CryptoRandom cryptoRandom = CryptoRandomFactory
                    .getCryptoRandom(SystemProperties.SYSTEM_PROPERTIES);
            if (JavaCryptoRandomDetector.isJavaCryptoRandom(cryptoRandom)) {
                return newFallbackCryptoRandom();
            }
            return new CryptoRandomGenerator(cryptoRandom);
        } catch (final GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static CryptoRandomGenerator newFallbackCryptoRandom() {
        return new CryptoRandomGenerator(new java.security.SecureRandom());
    }

}
