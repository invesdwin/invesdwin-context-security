package de.invesdwin.context.security.crypto.random;

import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.Immutable;

import io.netty.util.concurrent.FastThreadLocal;

@Immutable
public final class CryptoRandomGenerators {

    public static final String SHA1PRNG = "SHA1PRNG";
    public static final String NATIVE_PRNG = "NativePRNG";

    private static final FastThreadLocal<CryptoRandomGenerator> THREAD_LOCAL = new FastThreadLocal<CryptoRandomGenerator>() {
        @Override
        protected CryptoRandomGenerator initialValue() {
            return newCryptoRandom();
        }
    };

    private CryptoRandomGenerators() {}

    public static CryptoRandomGenerator getThreadLocalCryptoRandom() {
        final CryptoRandomGenerator instance = THREAD_LOCAL.get();
        instance.maybeReseed();
        return instance;
    }

    public static CryptoRandomGenerator newCryptoRandom(final byte[] seed) {
        try {
            //we need a software based implementation to be able to set a seed
            final java.security.SecureRandom secureRandom = java.security.SecureRandom.getInstance(SHA1PRNG);
            secureRandom.setSeed(seed);
            return new CryptoRandomGeneratorAdapter(secureRandom);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static CryptoRandomGeneratorAdapter newCryptoRandom(final long seed) {
        try {
            //we need a software based implementation to be able to set a seed
            final java.security.SecureRandom secureRandom = java.security.SecureRandom.getInstance(SHA1PRNG);
            secureRandom.setSeed(seed);
            return new CryptoRandomGeneratorAdapter(secureRandom);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Should use NativePRNG per default.
     */
    public static CryptoRandomGenerator newCryptoRandom() {
        return new CryptoRandomGenerator();
    }

}
