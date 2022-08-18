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
    private static final long ITERATIONS = 1000_000L;

    //java 17 1_000_000L
    //reuse instance
    //    SHA1PRNG (SecureRandom): PT0.160.357.017S
    //    CryptoRandom (NativePRNG): PT0.426.246.637S
    //    ThreadLocalCryptoRandom (NativePRNG): PT0.426.640.987S
    //    jdkDefault (NativePRNG): PT0.427.989.882S
    //    jdkStrong (Blocking): PT0.435.334.548S
    //    CryptoRandomGeneratorObjectPool: PT0.597.350.242S
    //    DRBG (Hash_DRBG,SHA-256,128,reseed_only): PT1.343.787.610S
    //    CommonsCryptoRandom (org.apache.commons.crypto.random.OpenSslCryptoRandom@31361438): PT3.262.986.210S
    //    Conscrypt (OpenSSLRandom): PT12.481.077.498S
    //    NIST800-90A/AES-CTR-256 (SPI): PT19.194.524.564S
    //    BC (Default): PT21.060.491.574S
    //don't reuse instance
    //    ThreadLocalCryptoRandom (NativePRNG): PT0.444.911.295S
    //    CryptoRandomGeneratorObjectPool: PT0.594.944.970S
    //    CryptoRandom (NativePRNG): PT5.213.024.488S
    //    DRBG (Hash_DRBG,SHA-256,128,reseed_only): PT8.989.698.500S
    //    jdkDefault (NativePRNG): PT9.343.835.394S
    //    SHA1PRNG (SecureRandom): PT10.105.693.074S
    //    CommonsCryptoRandom (org.apache.commons.crypto.random.OpenSslCryptoRandom@626e1e28): PT10.696.775.591S
    //    jdkStrong (Blocking): PT10.937.634.761S
    //    Conscrypt (OpenSSLRandom): PT23.088.978.549S
    //    NIST800-90A/AES-CTR-256 (SPI): PT25.019.633.121S
    //    BC (Default): PT32.565.073.770S

    //java 17 100_000L
    //reuse instance
    //    SHA1PRNG (SecureRandom): PT0.045.314.829S
    //    ThreadLocalCryptoRandom (NativePRNG): PT0.047.977.658S
    //    CryptoRandom (NativePRNG): PT0.056.428.670S
    //    jdkStrong (Blocking): PT0.057.592.178S
    //    jdkDefault (NativePRNG): PT0.061.186.862S
    //    CryptoRandomGeneratorObjectPool: PT0.127.597.149S
    //    DRBG (Hash_DRBG,SHA-256,128,reseed_only): PT0.178.526.617S
    //    CommonsCryptoRandom (org.apache.commons.crypto.random.OpenSslCryptoRandom@1e09e115): PT0.326.431.799S
    //    Conscrypt (OpenSSLRandom): PT1.209.693.993S
    //    NIST800-90A/AES-CTR-256 (SPI): PT1.935.196.270S
    //    BC (Default): PT2.120.230.548S
    //don't reuse instance
    //    ThreadLocalCryptoRandom (NativePRNG): PT0.046.923.892S
    //    CryptoRandomGeneratorObjectPool: PT0.151.448.101S
    //    CryptoRandom (NativePRNG): PT0.653.297.907S
    //    jdkDefault (NativePRNG): PT0.953.486.323S
    //    DRBG (Hash_DRBG,SHA-256,128,reseed_only): PT0.970.069.742S
    //    SHA1PRNG (SecureRandom): PT1.013.472.671S
    //    jdkStrong (Blocking): PT1.057.554.236S
    //    CommonsCryptoRandom (org.apache.commons.crypto.random.OpenSslCryptoRandom@2afd1646): PT1.062.824.014S
    //    Conscrypt (OpenSSLRandom): PT2.281.782.399S
    //    NIST800-90A/AES-CTR-256 (SPI): PT2.439.084.446S
    //    BC (Default): PT4.271.061.916S

    @Test
    public void testPerformance() throws Exception {
        testRandomPooledGenerator();
        testRandomGenerator("CryptoRandom", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return CryptoRandomGenerators.newCryptoRandom();
            }
        });
        testRandomGenerator("ThreadLocalCryptoRandom", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return CryptoRandomGenerators.getThreadLocalCryptoRandom();
            }
        });
        testRandomGenerator("DRBG", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGeneratorAdapter(java.security.SecureRandom.getInstance("DRBG"));
            }
        });
        testRandomGenerator("SHA1PRNG", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGeneratorAdapter(java.security.SecureRandom.getInstance("SHA1PRNG"));
            }
        });
        testRandomGenerator("jdkDefault", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGeneratorAdapter(new java.security.SecureRandom());
            }
        });
        testRandomGenerator("jdkStrong", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGeneratorAdapter(java.security.SecureRandom.getInstanceStrong());
            }
        });
        testRandomGenerator("CommonsCryptoRandom", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                final org.apache.commons.crypto.random.CryptoRandom cryptoRandom = CryptoRandomFactory
                        .getCryptoRandom();
                return new CommonsCryptoRandomGeneratorAdapter(cryptoRandom);
            }
        });
        testRandomGenerator("Conscrypt", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGeneratorAdapter(
                        java.security.SecureRandom.getInstance("SHA1PRNG", "Conscrypt"));
            }
        });
        if (AmazonCorrettoCryptoProvider.isRdRandSupported()) {
            testRandomGenerator("NIST800-90A/AES-CTR-256", new Callable<CryptoRandomGenerator>() {
                @Override
                public CryptoRandomGenerator call() throws Exception {
                    return new CryptoRandomGeneratorAdapter(java.security.SecureRandom
                            .getInstance("NIST800-90A/AES-CTR-256", "AmazonCorrettoCryptoProvider"));
                }
            });
        }
        testRandomGenerator("BC", new Callable<CryptoRandomGenerator>() {
            @Override
            public CryptoRandomGenerator call() throws Exception {
                return new CryptoRandomGeneratorAdapter(java.security.SecureRandom.getInstance("DEFAULT", "BC"));
            }
        });
    }

    private Duration testRandomGenerator(final String name, final Callable<CryptoRandomGenerator> random)
            throws Exception {
        final CryptoRandomGenerator instance = random.call();
        final Instant start = new Instant();
        for (long i = 0; i < ITERATIONS; i++) {
            instance.nextDouble();
        }
        final Duration duration = start.toDuration();
        //CHECKSTYLE:OFF
        System.out.println(name + " (" + instance + "): " + duration);
        //CHECKSTYLE:ON
        return duration;
    }

    private Duration testRandomPooledGenerator() throws Exception {
        final Instant start = new Instant();
        for (long i = 0; i < ITERATIONS; i++) {
            final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
            try {
                random.nextDouble();
            } finally {
                CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
            }
        }
        final Duration duration = start.toDuration();
        //CHECKSTYLE:OFF
        System.out.println("CryptoRandomGeneratorObjectPool: " + duration);
        //CHECKSTYLE:ON
        return duration;
    }

}
