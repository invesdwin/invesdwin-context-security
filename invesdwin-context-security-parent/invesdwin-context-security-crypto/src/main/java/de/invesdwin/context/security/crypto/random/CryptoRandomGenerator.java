package de.invesdwin.context.security.crypto.random;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.util.Set;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.util.collections.factory.ILockCollectionFactory;
import de.invesdwin.util.error.Throwables;
import de.invesdwin.util.math.random.IRandomGenerator;

@NotThreadSafe
public class CryptoRandomGenerator extends java.security.SecureRandom implements IRandomGenerator {

    private static final MethodHandle SUPER_RESEED_METHOD_HANDLE = newSuperReseedMethodHandle();
    private static final MethodHandle RESEED_METHOD_HANDLE = newReseedMethodHandle();

    private static final Set<String> RESEED_UNSUPPORTED_ALGORITHM = ILockCollectionFactory.getInstance(true)
            .newConcurrentSet();
    private static final boolean DEFAULT_RESEED_SUPPORTED = newDefaultReseedSupported();
    private static final long RESEED_UNSUPPORTED_NANOS = Long.MIN_VALUE;

    private long lastReseedNanos;

    public CryptoRandomGenerator(final String algorithm) {
        if (!RESEED_UNSUPPORTED_ALGORITHM.contains(algorithm)) {
            lastReseedNanos = System.nanoTime();
        } else {
            lastReseedNanos = RESEED_UNSUPPORTED_NANOS;
        }
    }

    public CryptoRandomGenerator(final boolean reseedSupported) {
        if (!reseedSupported) {
            lastReseedNanos = System.nanoTime();
        } else {
            lastReseedNanos = RESEED_UNSUPPORTED_NANOS;
        }
    }

    public CryptoRandomGenerator() {
        if (DEFAULT_RESEED_SUPPORTED) {
            lastReseedNanos = System.nanoTime();
        } else {
            lastReseedNanos = RESEED_UNSUPPORTED_NANOS;
        }
    }

    private static MethodHandle newSuperReseedMethodHandle() {
        try {
            final Lookup lookup = MethodHandles.lookup();
            return lookup.findSpecial(java.security.SecureRandom.class, "reseed", MethodType.methodType(void.class),
                    CryptoRandomGenerator.class);
        } catch (final Exception e) {
            return null;
        }
    }

    private static MethodHandle newReseedMethodHandle() {
        try {
            final Method reseed = java.security.SecureRandom.class.getDeclaredMethod("reseed");
            final Lookup lookup = MethodHandles.lookup();
            return lookup.unreflect(reseed);
        } catch (final Exception e) {
            return null;
        }
    }

    private static boolean newDefaultReseedSupported() {
        final java.security.SecureRandom defaultInstance = new java.security.SecureRandom();
        return newReseedSupported(defaultInstance);
    }

    public static boolean newReseedSupported(final java.security.SecureRandom instance) {
        try {
            reseed(instance);
            return true;
        } catch (final UnsupportedOperationException e) {
            RESEED_UNSUPPORTED_ALGORITHM.add(instance.getAlgorithm());
            return false;
        }
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

    @Override
    public void reseed() {
        reseedIfSupported();
    }

    protected void reseedIfSupported(final java.security.SecureRandom delegate) {
        if (lastReseedNanos == RESEED_UNSUPPORTED_NANOS) {
            return;
        }
        try {
            reseed(delegate);
        } catch (final UnsupportedOperationException e) {
            /*
             * no need to fallback to setSeed instead because e.g. NativePRNG gives the seed to the operating system
             * which already includes the system time
             */
            RESEED_UNSUPPORTED_ALGORITHM.add(getAlgorithm());
            lastReseedNanos = RESEED_UNSUPPORTED_NANOS;
        }
    }

    protected void reseedIfSupported() {
        if (lastReseedNanos == RESEED_UNSUPPORTED_NANOS) {
            return;
        }
        try {
            reseed(this);
        } catch (final UnsupportedOperationException e) {
            /*
             * no need to fallback to setSeed instead because e.g. NativePRNG gives the seed to the operating system
             * which already includes the system time
             */
            RESEED_UNSUPPORTED_ALGORITHM.add(getAlgorithm());
            lastReseedNanos = RESEED_UNSUPPORTED_NANOS;
        }
    }

    public void maybeReseed() {
        if (lastReseedNanos == RESEED_UNSUPPORTED_NANOS) {
            return;
        }
        final long currentNanos = System.nanoTime();
        if (CryptoProperties.RESEED_INTERVAL.isLessThanOrEqualToNanos(currentNanos - lastReseedNanos)) {
            reseed();
            lastReseedNanos = currentNanos;
        }
    }

    public static void reseed(final CryptoRandomGenerator random) {
        if (SUPER_RESEED_METHOD_HANDLE != null) {
            try {
                SUPER_RESEED_METHOD_HANDLE.invoke(random);
            } catch (final Throwable e) {
                throw Throwables.propagate(e);
            }
        } else {
            random.setSeed(System.currentTimeMillis() + System.identityHashCode(random));
        }
    }

    /**
     * A version of reseed that is backwards compatible to java 8.
     */
    public static void reseed(final java.security.SecureRandom random) {
        if (RESEED_METHOD_HANDLE != null) {
            try {
                RESEED_METHOD_HANDLE.invoke(random);
            } catch (final Throwable e) {
                throw Throwables.propagate(e);
            }
        } else {
            random.setSeed(System.currentTimeMillis() + System.identityHashCode(random));
        }
    }

}
