package de.invesdwin.context.security.crypto.key.password.argon2.unsafe;

import javax.annotation.concurrent.NotThreadSafe;

import org.junit.jupiter.api.Test;

import de.invesdwin.context.log.Log;
import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.key.password.PasswordHasherBenchmarkResult;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2PasswordHasherBenchmarkIterations;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2PasswordHasherBenchmarkMemory;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.jvm.Argon2PasswordHasher;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerators;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.concurrent.Executors;
import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@NotThreadSafe
public class NativeArgon2PasswordHasherTest {

    private final Log log = new Log(this);

    /**
     * first test memory, then iterations (do at least 4 iterations):
     * https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/
     */
    @Test
    public void testDuration() {
        final Duration maxDuration = new Duration(200, FTimeUnit.MILLISECONDS);
        final Argon2PasswordHasherBenchmarkMemory benchmarkFirst = new Argon2PasswordHasherBenchmarkMemory() {
            @Override
            public IArgon2PasswordHasher getDefaultInstance() {
                return NativeArgon2PasswordHasher.DEFAULT;
            }
        };
        final PasswordHasherBenchmarkResult<IArgon2PasswordHasher> benchmarkWorkFactorResult = benchmarkFirst
                .benchmarkReport(maxDuration);

        final Argon2PasswordHasherBenchmarkIterations benchmarkSecond = new Argon2PasswordHasherBenchmarkIterations() {
            @Override
            public IArgon2PasswordHasher newInitialCostInstance() {
                return benchmarkWorkFactorResult.getInstance();
            }
        };
        benchmarkSecond.benchmarkReport(maxDuration);
    }

    @Test
    public void testDurationReverse() {
        final Duration maxDuration = new Duration(200, FTimeUnit.MILLISECONDS);
        final Argon2PasswordHasherBenchmarkIterations benchmarkFirst = new Argon2PasswordHasherBenchmarkIterations() {
            @Override
            public IArgon2PasswordHasher getDefaultInstance() {
                return NativeArgon2PasswordHasher.DEFAULT;
            }
        };
        final PasswordHasherBenchmarkResult<IArgon2PasswordHasher> benchmarkWorkFactorResult = benchmarkFirst
                .benchmarkReport(maxDuration);

        final Argon2PasswordHasherBenchmarkMemory benchmarkSecond = new Argon2PasswordHasherBenchmarkMemory() {
            @Override
            public IArgon2PasswordHasher newInitialCostInstance() {
                return benchmarkWorkFactorResult.getInstance();
            }
        };
        benchmarkSecond.benchmarkReport(maxDuration);
    }

    @Test
    public void testParallelisation() {
        final int length = 64;
        final byte[] salt = new byte[length];
        final byte[] password = new byte[length];
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        random.nextBytes(salt);
        random.nextBytes(password);
        byte[] prevResult = null;
        final int maxParallelisation = Executors.getCpuThreadPoolCount();
        for (int parallelisation = 1; parallelisation <= maxParallelisation; parallelisation++) {
            final NativeArgon2PasswordHasher argon2 = new NativeArgon2PasswordHasher(CryptoProperties.DEFAULT_PEPPER,
                    NativeArgon2PasswordHasher.DEFAULT_TYPE, NativeArgon2PasswordHasher.DEFAULT_VERSION,
                    NativeArgon2PasswordHasher.DEFAULT_MEMORY, NativeArgon2PasswordHasher.DEFAULT_ITERATIONS,
                    parallelisation);
            final Argon2PasswordHasher argon2Reference = new Argon2PasswordHasher(CryptoProperties.DEFAULT_PEPPER,
                    NativeArgon2PasswordHasher.DEFAULT_TYPE, NativeArgon2PasswordHasher.DEFAULT_VERSION,
                    NativeArgon2PasswordHasher.DEFAULT_MEMORY, NativeArgon2PasswordHasher.DEFAULT_ITERATIONS,
                    parallelisation);
            final byte[] result = argon2.hash(salt, password, length);
            final byte[] resultReference = argon2Reference.hash(salt, password, length);
            final boolean same = Objects.equals(result, resultReference);
            log.info("Same[" + parallelisation + "]: " + same);
            Assertions.checkTrue(same);
            if (prevResult != null) {
                final boolean different = Objects.equals(result, prevResult);
                log.info("Prev[" + parallelisation + "]: " + different);
                Assertions.checkFalse(different);
            }
            prevResult = result;
        }
    }

}
