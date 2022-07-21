package de.invesdwin.context.security.crypto.key.password;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.log.Log;
import de.invesdwin.context.security.crypto.authentication.mac.hmac.HmacAlgorithm;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.util.time.Instant;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

/**
 * Adapted from com.password4j.SystemChecker
 */
@Immutable
public abstract class APasswordHasherBenchmark<E extends IPasswordHasher> {

    private static final byte[] PASSWORD = "abcDEF123@~# xyz+-*/=456spqr".getBytes();
    private static final byte[] SALT;
    private static final int BENCHMARK_ROUNDS = 20;
    private static final int LENGTH = HmacAlgorithm.HMAC_SHA_256.getMacLength();
    private static final int MAX_TRIES = 10;

    private final Log log = new Log(this);

    static {
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] salt = new byte[64];
            random.nextBytes(salt);
            SALT = salt;
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
    }

    public abstract E getDefaultInstance();

    public abstract E newHighMemoryInstance();

    public abstract E newIterationsInstance(E previousInstance, int iterations);

    /**
     * Should throw an exception if this is not possible or not desired.
     */
    protected abstract E newReducedMemoryInstance(E previousInstance);

    public PasswordHasherBenchmarkResult<E> benchmark() {
        return benchmark(getDefaultInstance());
    }

    public PasswordHasherBenchmarkResult<E> benchmark(final E instance) {
        final Instant start = new Instant();
        for (int i = 0; i < BENCHMARK_ROUNDS; i++) {
            instance.hash(SALT, PASSWORD, LENGTH);
        }
        final Duration duration = start.toDuration().divide(BENCHMARK_ROUNDS);
        return new PasswordHasherBenchmarkResult<E>(duration, instance);
    }

    public PasswordHasherBenchmarkResult<E> benchmarkIterations(final Duration maxDuration, final boolean logProgress) {
        final long maxMilliseconds = maxDuration.longValue(FTimeUnit.MILLISECONDS);
        long finalElapsed = -1;
        int iterations = getInitialIterations();
        E suitableInstance = null;

        E currentInstance = newIterationsInstance(newHighMemoryInstance(), iterations);

        for (int i = 0; i < MAX_TRIES; i++) {
            while (true) {
                final long start = System.currentTimeMillis();

                currentInstance.hash(SALT, PASSWORD, LENGTH);

                final long end = System.currentTimeMillis();
                final long elapsed = end - start;

                if (elapsed > maxMilliseconds) {
                    if (logProgress) {
                        log.info("Exceeded: %s", new PasswordHasherBenchmarkResult<E>(
                                new Duration(elapsed, FTimeUnit.MILLISECONDS), currentInstance));
                    }
                    break;
                } else {
                    finalElapsed = elapsed;
                    suitableInstance = currentInstance;
                    if (logProgress) {
                        log.info("Increased: %s", new PasswordHasherBenchmarkResult<E>(
                                new Duration(elapsed, FTimeUnit.MILLISECONDS), currentInstance));
                    }
                    iterations = increaseIterations(iterations);
                    currentInstance = newIterationsInstance(currentInstance, iterations);
                }
            }

            if (finalElapsed == -1) {
                currentInstance = newReducedMemoryInstance(currentInstance);
            } else {
                break;
            }
        }

        return new PasswordHasherBenchmarkResult<>(new Duration(finalElapsed, FTimeUnit.MILLISECONDS),
                suitableInstance);
    }

    protected abstract int increaseIterations(int iterations);

    protected abstract int getInitialIterations();

    public PasswordHasherBenchmarkResult<E> benchmarkReport(final Duration maxDuration) {
        log.info("MaxDuration: %s", maxDuration);
        log.info("Warmup: %s", benchmark());
        log.info("Default: %s", benchmark());
        final PasswordHasherBenchmarkResult<E> suitable = benchmarkIterations(maxDuration, true);
        log.info("Suitable: %s", suitable);
        return suitable;
    }

}
