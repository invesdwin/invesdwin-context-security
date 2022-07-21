package de.invesdwin.context.security.crypto.key.password.pbkdf2;

import javax.annotation.concurrent.NotThreadSafe;

import org.junit.jupiter.api.Test;

import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@NotThreadSafe
public class Pbkdf2PasswordHasherTest {

    @Test
    public void testDuration() {
        final Pbkdf2PasswordHasherBenchmarkIterations benchmark = new Pbkdf2PasswordHasherBenchmarkIterations();
        benchmark.benchmarkReport(new Duration(200, FTimeUnit.MILLISECONDS));
    }

}
