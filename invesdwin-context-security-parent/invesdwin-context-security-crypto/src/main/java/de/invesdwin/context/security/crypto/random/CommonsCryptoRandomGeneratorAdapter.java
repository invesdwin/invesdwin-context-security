package de.invesdwin.context.security.crypto.random;

import java.io.Closeable;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.concurrent.reference.IReference;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.lang.finalizer.AFinalizer;

/**
 * Consider using JavaCryptoRandomDetector as a safe alternative to instantiate this.
 */
@Immutable
public class CommonsCryptoRandomGeneratorAdapter extends CryptoRandomGenerator implements Closeable {

    private final CryptoRandomGeneratorFinalizer finalizer;

    public CommonsCryptoRandomGeneratorAdapter(final org.apache.commons.crypto.random.CryptoRandom delegate) {
        super(false);
        this.finalizer = new CryptoRandomGeneratorFinalizer(delegate);
        finalizer.register(this);
    }

    @Override
    public String getAlgorithm() {
        return finalizer.random.getClass().getSimpleName();
    }

    @Override
    public String toString() {
        return finalizer.random.toString();
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
    public void reseed() {
        finalizer.random.setSeed(System.currentTimeMillis() + System.identityHashCode(this));
    }

    @Override
    public void nextBytes(final byte[] bytes) {
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

    @Override
    public void close() {
        finalizer.close();
    }

    private static final class CryptoRandomGeneratorFinalizer extends AFinalizer
            implements IReference<java.util.Random> {
        private org.apache.commons.crypto.random.CryptoRandom cryptoRandom;
        private java.util.Random random;

        private CryptoRandomGeneratorFinalizer(final org.apache.commons.crypto.random.CryptoRandom cryptoRandom) {
            this.cryptoRandom = cryptoRandom;
            this.random = (java.util.Random) cryptoRandom;
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

        @Override
        public java.util.Random get() {
            return random;
        }

    }

}
