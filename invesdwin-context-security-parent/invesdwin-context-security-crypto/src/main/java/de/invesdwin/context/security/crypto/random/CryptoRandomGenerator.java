package de.invesdwin.context.security.crypto.random;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.math.random.IRandomGenerator;

@Immutable
public class CryptoRandomGenerator extends java.security.SecureRandom implements IRandomGenerator {

    public CryptoRandomGenerator() {
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

}
