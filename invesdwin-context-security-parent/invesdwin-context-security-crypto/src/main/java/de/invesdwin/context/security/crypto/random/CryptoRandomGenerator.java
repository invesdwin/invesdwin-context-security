package de.invesdwin.context.security.crypto.random;

import java.io.Closeable;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.concurrent.reference.IReference;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.lang.finalizer.AFinalizer;
import de.invesdwin.util.math.random.IRandomGenerator;

@Immutable
public class CryptoRandomGenerator extends java.security.SecureRandom implements IRandomGenerator, Closeable {

    private final CryptoRandomGeneratorFinalizer finalizer;

    public CryptoRandomGenerator(final java.security.SecureRandom delegate) {
        this.finalizer = new CryptoRandomGeneratorFinalizer(delegate);
        //no need to register finalizer because SecureRandom does not need to be closed
    }

    public CryptoRandomGenerator(final org.apache.commons.crypto.random.CryptoRandom delegate) {
        this.finalizer = new CryptoRandomGeneratorFinalizer(delegate);
        finalizer.register(this);
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

    @Override
    public float nextFloat(final float minInclusive, final float maxExclusive) {
        return IRandomGenerator.super.nextFloat(minInclusive, maxExclusive);
    }

    @Override
    public double nextDouble(final double maxExclusive) {
        return IRandomGenerator.super.nextDouble(maxExclusive);
    }

    @Override
    public int nextInt(final int minInclusive, final int maxExclusive) {
        return IRandomGenerator.super.nextInt(minInclusive, maxExclusive);
    }

    @Override
    public float nextFloat(final float maxExclusive) {
        return IRandomGenerator.super.nextFloat(maxExclusive);
    }

    @Override
    public long nextLong(final long maxExclusive) {
        return IRandomGenerator.super.nextLong(maxExclusive);
    }

    @Override
    public double nextDouble(final double minInclusive, final double maxExclusive) {
        return IRandomGenerator.super.nextDouble(minInclusive, maxExclusive);
    }

    @Override
    public long nextLong(final long minInclusive, final long maxExclusive) {
        return IRandomGenerator.super.nextLong(minInclusive, maxExclusive);
    }

    @Override
    public double nextGaussian(final double mean, final double stddev) {
        return IRandomGenerator.super.nextGaussian(mean, stddev);
    }

    @Override
    public double nextExponential() {
        return IRandomGenerator.super.nextExponential();
    }

    private static final class CryptoRandomGeneratorFinalizer extends AFinalizer
            implements IReference<java.util.Random> {
        private org.apache.commons.crypto.random.CryptoRandom cryptoRandom;
        private java.util.Random random;

        private CryptoRandomGeneratorFinalizer(final java.security.SecureRandom secureRandom) {
            this.random = secureRandom;
        }

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
