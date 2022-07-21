package de.invesdwin.context.security.crypto.key.password.scrypt;

import javax.annotation.concurrent.NotThreadSafe;

import org.junit.jupiter.api.Test;

import de.invesdwin.context.security.crypto.key.password.PasswordHasherBenchmarkResult;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@NotThreadSafe
public class ScryptPasswordHasherTest {

    /**
     * first test work factor, then resources: https://github.com/Password4j/password4j/wiki/Recommended-settings#scrypt
     */
    @Test
    public void testDuration() {
        final Duration maxDuration = new Duration(200, FTimeUnit.MILLISECONDS);
        final ScryptPasswordHasherBenchmarkWorkFactor benchmarkFirst = new ScryptPasswordHasherBenchmarkWorkFactor();
        final PasswordHasherBenchmarkResult<ScryptPasswordHasher> benchmarkWorkFactorResult = benchmarkFirst
                .benchmarkReport(maxDuration);

        final ScryptPasswordHasherBenchmarkResources benchmarkSecond = new ScryptPasswordHasherBenchmarkResources() {
            @Override
            public ScryptPasswordHasher newInitialCostInstance() {
                return benchmarkWorkFactorResult.getInstance();
            }
        };
        benchmarkSecond.benchmarkReport(maxDuration);
    }

    /**
     * first test work factor, then resources: https://github.com/Password4j/password4j/wiki/Recommended-settings#scrypt
     */
    @Test
    public void testDurationReverse() {
        final Duration maxDuration = new Duration(200, FTimeUnit.MILLISECONDS);
        final ScryptPasswordHasherBenchmarkResources benchmarkFirst = new ScryptPasswordHasherBenchmarkResources();
        final PasswordHasherBenchmarkResult<ScryptPasswordHasher> benchmarkWorkFactorResult = benchmarkFirst
                .benchmarkReport(maxDuration);

        final ScryptPasswordHasherBenchmarkWorkFactor benchmarkSecond = new ScryptPasswordHasherBenchmarkWorkFactor() {
            @Override
            public ScryptPasswordHasher newInitialCostInstance() {
                return benchmarkWorkFactorResult.getInstance();
            }
        };
        benchmarkSecond.benchmarkReport(maxDuration);
    }

}
