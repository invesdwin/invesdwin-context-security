package de.invesdwin.context.security.crypto.random;

import java.util.concurrent.Callable;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;

import de.invesdwin.context.test.ATest;
import de.invesdwin.util.time.Instant;
import de.invesdwin.util.time.duration.Duration;

@Disabled("manual test")
@NotThreadSafe
public class CryptoRandomGeneratorsTest extends ATest {
    //java 17
    //reuse instance
    //    SHA1PRNG (SecureRandom): PT0.024.923.691S
    //    jdkStrong (Blocking): PT0.048.900.035S
    //    jdkDefault (NativePRNG): PT0.051.416.371S
    //    DRBG (Hash_DRBG,SHA-256,128,reseed_only): PT0.192.175.263S
    //    CryptoRandom (org.apache.commons.crypto.random.OpenSslCryptoRandom@64b42529): PT0.388.719.800S
    //    Conscrypt (OpenSSLRandom): PT1.219.229.436S
    //    NIST800-90A/AES-CTR-256 (SPI): PT2.049.196.043S
    //don't reuse instance
    //    DRBG (Hash_DRBG,SHA-256,128,reseed_only): PT0.985.480.696S
    //    jdkDefault (NativePRNG): PT1.004.432.592S
    //    SHA1PRNG (SecureRandom): PT1.101.178.442S
    //    jdkStrong (Blocking): PT1.128.303.357S
    //    CryptoRandom (org.apache.commons.crypto.random.OpenSslCryptoRandom@64b42529): PT1.344.538.116S
    //    Conscrypt (OpenSSLRandom): PT2.243.130.114S
    //    NIST800-90A/AES-CTR-256 (SPI): PT2.347.941.927S
    @Test
    public void testPerformance() throws Exception {
        testRandomGenerator("CryptoRandom", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                final org.apache.commons.crypto.random.CryptoRandom cryptoRandom = CryptoRandomFactory
                        .getCryptoRandom();
                return new CryptoRandomGenerator(cryptoRandom);
            }
        });
        if (AmazonCorrettoCryptoProvider.isRdRandSupported()) {
            testRandomGenerator("NIST800-90A/AES-CTR-256", new Callable<CryptoRandomGenerator>() {
                @Override
                public CryptoRandomGenerator call() throws Exception {
                    return new CryptoRandomGenerator(java.security.SecureRandom.getInstance("NIST800-90A/AES-CTR-256",
                            "AmazonCorrettoCryptoProvider"));
                }
            });
        }
        testRandomGenerator("Conscrypt", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGenerator(java.security.SecureRandom.getInstance("SHA1PRNG", "Conscrypt"));
            }
        });

        testRandomGenerator("DRBG", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGenerator(java.security.SecureRandom.getInstance("DRBG"));
            }
        });
        testRandomGenerator("SHA1PRNG", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGenerator(java.security.SecureRandom.getInstance("SHA1PRNG"));
            }
        });
        testRandomGenerator("jdkDefault", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGenerator(new java.security.SecureRandom());
            }
        });
        testRandomGenerator("jdkStrong", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGenerator(java.security.SecureRandom.getInstanceStrong());
            }
        });
    }

    private Duration testRandomGenerator(final String name, final Callable<CryptoRandomGenerator> random)
            throws Exception {
        final Instant start = new Instant();
        for (long i = 0; i < 100000L; i++) {
            random.call().nextDouble();
        }
        final Duration duration = start.toDuration();
        //CHECKSTYLE:OFF
        System.out.println(name + " (" + random.call() + "): " + duration);
        //CHECKSTYLE:ON
        return duration;
    }

}
