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
        final ScryptPasswordHasherBenchmarkWorkFactor benchmarkWorkFactor = new ScryptPasswordHasherBenchmarkWorkFactor();
        final PasswordHasherBenchmarkResult<ScryptPasswordHasher> benchmarkWorkFactorResult = benchmarkWorkFactor
                .benchmarkReport(maxDuration);

        final ScryptPasswordHasherBenchmarkResources benchmarkResources = new ScryptPasswordHasherBenchmarkResources() {
            @Override
            public ScryptPasswordHasher newHighMemoryInstance() {
                return benchmarkWorkFactorResult.getInstance();
            }
        };
        benchmarkResources.benchmarkReport(maxDuration);
    }

}
