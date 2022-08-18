package de.invesdwin.context.security.crypto.random.strong;

import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import io.netty.util.concurrent.FastThreadLocal;

/**
 * Some situations require strong random values, such as when creating high-value/long-lived secrets like RSA
 * public/private keys.
 *
 * WARNING: performance will degrade significantly if entropy is exhausted
 * (https://tersesystems.com/blog/2015/12/17/the-right-way-to-use-securerandom/)
 * (https://tanzu.vmware.com/content/blog/challenges-with-randomness-in-multi-tenant-linux-container-platforms)
 * 
 * Needs to be reseeded regularly (https://metebalci.com/blog/everything-about-javas-securerandom/)
 * 
 * regarding RDRAND exploits: https://en.wikipedia.org/wiki/RDRAND
 * 
 * /dev/random mixes RDRAND into the randomness pool. So there is no need to explicitly call a native function for this.
 * /dev/random is fine as it is. (https://security.stackexchange.com/questions/42164/rdrand-from-dev-random)
 * 
 * If you are unsure about whether you should use /dev/random or /dev/urandom, then probably you want to use the latter.
 * As a general rule, /dev/urandom should be used for everything except long-lived GPG/SSL/SSH keys.
 * (https://www.2uo.de/myths-about-urandom/)
 * (https://unix.stackexchange.com/questions/324209/when-to-use-dev-random-vs-dev-urandom)
 */
@Immutable
public final class StrongRandomGenerators {

    private static final String DRBG = "DRBG";
    private static final boolean DRBG_AVAILABLE = newDrbgAvailable();
    private static final boolean RESEED_SUPPORTED = newReseedSupported();

    private static final FastThreadLocal<StrongRandomGenerator> THREAD_LOCAL = new FastThreadLocal<StrongRandomGenerator>() {
        @Override
        protected StrongRandomGenerator initialValue() {
            return newStrongRandom();
        }
    };

    private StrongRandomGenerators() {}

    private static boolean newReseedSupported() {
        final java.security.SecureRandom instance = newSecureRandom();
        return CryptoRandomGenerator.newReseedSupported(instance);
    }

    private static boolean newDrbgAvailable() {
        try {
            final java.security.SecureRandom drbg = java.security.SecureRandom.getInstance(DRBG);
            return drbg != null;
        } catch (final NoSuchAlgorithmException e) {
            return false;
        }
    }

    public static StrongRandomGenerator getThreadLocalStrongRandom() {
        final StrongRandomGenerator random = THREAD_LOCAL.get();
        random.maybeReseed();
        return random;
    }

    public static StrongRandomGenerator newStrongRandom() {
        return new StrongRandomGenerator(newSecureRandom(), RESEED_SUPPORTED);
    }

    private static java.security.SecureRandom newSecureRandom() {
        try {
            if (DRBG_AVAILABLE) {
                /*
                 * Using DRBG should not be as slow as using /dev/random, since it reads entropy only during reseeds and
                 * otherwise uses a hash digest to come up with new random values.
                 * 
                 * This should be helpful in shared hosting environments.
                 */
                return java.security.SecureRandom.getInstance(DRBG);
            } else {
                return java.security.SecureRandom.getInstanceStrong();
            }
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
