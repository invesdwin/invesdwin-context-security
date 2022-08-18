package de.invesdwin.context.security.crypto.random;

import javax.annotation.concurrent.Immutable;

@Immutable
public class CryptoRandomGeneratorAdapter extends CryptoRandomGenerator {

    private final java.security.SecureRandom delegate;

    public CryptoRandomGeneratorAdapter(final java.security.SecureRandom delegate, final boolean reseedSupported) {
        super(reseedSupported);
        this.delegate = delegate;
    }

    public CryptoRandomGeneratorAdapter(final java.security.SecureRandom delegate) {
        super(delegate.getAlgorithm());
        this.delegate = delegate;
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public String toString() {
        return delegate.toString();
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
        if (delegate == null) {
            //super constructor
            return;
        }
        delegate.setSeed(seed);
    }

    @Override
    public void nextBytes(final byte[] bytes) {
        delegate.nextBytes(bytes);
    }

    @Override
    public int nextInt() {
        return delegate.nextInt();
    }

    @Override
    public int nextInt(final int n) {
        return delegate.nextInt(n);
    }

    @Override
    public long nextLong() {
        return delegate.nextLong();
    }

    @Override
    public boolean nextBoolean() {
        return delegate.nextBoolean();
    }

    @Override
    public float nextFloat() {
        return delegate.nextFloat();
    }

    @Override
    public double nextDouble() {
        return delegate.nextDouble();
    }

    @Override
    public double nextGaussian() {
        return delegate.nextGaussian();
    }

    @Override
    public void reseed() {
        reseedIfSupported(delegate);
    }

}
