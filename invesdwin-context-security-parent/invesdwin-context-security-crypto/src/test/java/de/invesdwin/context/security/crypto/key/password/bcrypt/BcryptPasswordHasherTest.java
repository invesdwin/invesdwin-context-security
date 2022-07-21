package de.invesdwin.context.security.crypto.key.password.bcrypt;

import javax.annotation.concurrent.NotThreadSafe;

import org.junit.jupiter.api.Test;

import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@NotThreadSafe
public class BcryptPasswordHasherTest {

    @Test
    public void testDuration() {
        final BcryptPasswordHasherBenchmarkLogRounds benchmark = new BcryptPasswordHasherBenchmarkLogRounds();
        benchmark.benchmarkReport(new Duration(200, FTimeUnit.MILLISECONDS));
    }

}
