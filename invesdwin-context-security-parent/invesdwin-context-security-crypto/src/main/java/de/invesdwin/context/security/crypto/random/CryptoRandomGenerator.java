package de.invesdwin.context.security.crypto.random;

import java.io.Closeable;
import java.security.SecureRandomParameters;
import java.util.Random;

import javax.annotation.concurrent.Immutable;

import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.math3.random.RandomGenerator;

import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.lang.finalizer.AFinalizer;

@Immutable
public class CryptoRandomGenerator extends java.security.SecureRandom implements RandomGenerator, Closeable {

    private final CryptoRandomGeneratorFinalizer finalizer;

    public CryptoRandomGenerator(final CryptoRandom delegate) {
        this.finalizer = new CryptoRandomGeneratorFinalizer(delegate);
        finalizer.register(this);
    }

    @Override
    public void setSeed(final int seed) {
        setSeed((long) seed);
    }

    @Override
    public void setSeed(final int[] seed) {
        // the following number is the largest prime that fits in 32 bits (it is 2^32 - 5)
        final long prime = 4294967291L;

        long combined = 0L;
        for (int i = 0; i < seed.length; i++) {
            combined = combined * prime + seed[i];
        }
        setSeed(combined);
    }

    @Override
    public void setSeed(final byte[] seed) {
        // the following number is the largest prime that fits in 32 bits (it is 2^32 - 5)
        final long prime = 4294967291L;

        long combined = 0L;
        for (int i = 0; i < seed.length; i++) {
            combined = combined * prime + seed[i];
        }
        setSeed(combined);
    }

    @Override
    public void setSeed(final long seed) {
        if (finalizer == null) {
            //super constructor
            return;
        }
        finalizer.random.setSeed(seed);
    }

    @Override
    public void nextBytes(final byte[] bytes) {
        finalizer.random.nextBytes(bytes);
    }

    @Deprecated
    @Override
    public void nextBytes(final byte[] bytes, final SecureRandomParameters params) {
        finalizer.random.nextBytes(bytes);
    }

    @Override
    public int nextInt() {
        return finalizer.random.nextInt();
    }

    @Override
    public int nextInt(final int n) {
        return finalizer.random.nextInt(n);
    }

    @Override
    public long nextLong() {
        return finalizer.random.nextLong();
    }

    @Override
    public boolean nextBoolean() {
        return finalizer.random.nextBoolean();
    }

    @Override
    public float nextFloat() {
        return finalizer.random.nextFloat();
    }

    @Override
    public double nextDouble() {
        return finalizer.random.nextDouble();
    }

    @Override
    public double nextGaussian() {
        return finalizer.random.nextGaussian();
    }

    @Deprecated
    @Override
    public void reseed() {
        //noop
    }

    @Deprecated
    @Override
    public void reseed(final SecureRandomParameters params) {
        //noop
    }

    @Override
    public void close() {
        finalizer.close();
    }

    private static final class CryptoRandomGeneratorFinalizer extends AFinalizer {
        private CryptoRandom cryptoRandom;
        private Random random;

        private CryptoRandomGeneratorFinalizer(final CryptoRandom cryptoRandom) {
            this.cryptoRandom = cryptoRandom;
            this.random = (Random) cryptoRandom;
        }

        @Override
        protected void clean() {
            if (cryptoRandom != null) {
                Closeables.closeQuietly(cryptoRandom);
                cryptoRandom = null;
                random = null;
            }
        }

        @Override
        protected boolean isCleaned() {
            return cryptoRandom == null;
        }

        @Override
        public boolean isThreadLocal() {
            return false;
        }

    }

}
