package de.invesdwin.context.security.crypto.key.password;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.log.Log;
import de.invesdwin.context.security.crypto.authentication.mac.algorithm.IMacAlgorithm;
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
    private static final int LENGTH = IMacAlgorithm.DEFAULT.getMacLength();
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

    public abstract E newInitialCostInstance();

    public abstract E newCostInstance(E previousInstance, int iterations);

    /**
     * Should throw an exception if this is not possible or not desired.
     */
    protected abstract E newReducedOtherCostInstance(E previousInstance);

    public PasswordHasherBenchmarkResult<E> benchmark() {
        return benchmark(getDefaultInstance());
    }

    public PasswordHasherBenchmarkResult<E> benchmark(final E instance) {
        final Instant start = new Instant();
        for (int i = 0; i < BENCHMARK_ROUNDS; i++) {
            instance.hash(SALT, PASSWORD, LENGTH);
        }
        final Duration duration = start.toDuration().divide(BENCHMARK_ROUNDS);
        return new PasswordHasherBenchmarkResult<E>(duration, null, -1, instance);
    }

    public PasswordHasherBenchmarkResult<E> benchmarkIterations(final Duration maxDuration, final boolean logProgress) {
        final long maxMilliseconds = maxDuration.longValue(FTimeUnit.MILLISECONDS);
        long finalElapsed = -1;
        int cost = getInitialCost();
        int suitableCost = cost;
        E suitableInstance = null;

        E currentInstance = newCostInstance(newInitialCostInstance(), cost);

        for (int i = 0; i < MAX_TRIES; i++) {
            while (true) {
                final long start = System.currentTimeMillis();

                currentInstance.hash(SALT, PASSWORD, LENGTH);

                final long end = System.currentTimeMillis();
                final long elapsed = end - start;

                if (elapsed > maxMilliseconds) {
                    if (logProgress) {
                        final Duration duration = new Duration(elapsed, FTimeUnit.MILLISECONDS);
                        log.info("Exceeded: %s",
                                new PasswordHasherBenchmarkResult<E>(duration, getCostName(), cost, currentInstance));
                    }
                    break;
                } else {
                    finalElapsed = elapsed;
                    suitableInstance = currentInstance;
                    suitableCost = cost;
                    if (logProgress) {
                        final Duration duration = new Duration(elapsed, FTimeUnit.MILLISECONDS);
                        log.info("Increased: %s", new PasswordHasherBenchmarkResult<E>(duration, getCostName(),
                                suitableCost, currentInstance));
                    }
                    cost = increaseCost(cost);
                    currentInstance = newCostInstance(currentInstance, cost);
                }
            }

            if (finalElapsed == -1) {
                currentInstance = newReducedOtherCostInstance(currentInstance);
            } else {
                break;
            }
        }

        final Duration duration = new Duration(finalElapsed, FTimeUnit.MILLISECONDS);
        return new PasswordHasherBenchmarkResult<>(duration, getCostName(), suitableCost, suitableInstance);
    }

    protected abstract String getCostName();

    protected abstract int getInitialCost();

    protected abstract int increaseCost(int cost);

    public PasswordHasherBenchmarkResult<E> benchmarkReport(final Duration maxDuration) {
        log.info("MaxDuration: %s", maxDuration);
        log.info("Warmup: %s", benchmark());
        log.info("Default: %s", benchmark());
        final PasswordHasherBenchmarkResult<E> suitable = benchmarkIterations(maxDuration, true);
        log.info("Suitable: %s", suitable);
        return suitable;
    }

}
