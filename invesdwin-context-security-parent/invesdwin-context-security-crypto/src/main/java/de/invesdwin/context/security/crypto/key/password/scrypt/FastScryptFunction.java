package de.invesdwin.context.security.crypto.key.password.scrypt;

import javax.annotation.concurrent.Immutable;

import com.password4j.ScryptFunction;

import de.invesdwin.context.security.crypto.key.password.pbkdf2.Pbkdf2PasswordHasher;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HmacAlgorithm;
import de.invesdwin.util.math.Bytes;

@Immutable
public class FastScryptFunction extends ScryptFunction {

    /**
     * About 200ms on an I9-9900K
     */
    public static final int DEFAULT_WORK_FACTOR = 8;
    public static final int DEFAULT_RESOURCES = 1 << 14;
    public static final int DEFAULT_PARALLELIZATION = 1;

    public static final FastScryptFunction INSTANCE = new FastScryptFunction(DEFAULT_WORK_FACTOR, DEFAULT_RESOURCES,
            DEFAULT_PARALLELIZATION);

    private static final Pbkdf2PasswordHasher PBKDF2_HMAC_SHA256_SINGLE_ITERATION_NO_PEPPER = new Pbkdf2PasswordHasher(
            Bytes.EMPTY_ARRAY, 1, HmacAlgorithm.HMAC_SHA_256);

    public FastScryptFunction() {
        this(DEFAULT_WORK_FACTOR, DEFAULT_RESOURCES, DEFAULT_PARALLELIZATION);
    }

    public FastScryptFunction(final int workFactor, final int resources, final int parallelization) {
        super(workFactor, resources, parallelization);
        if (workFactor >= 2 && (workFactor & workFactor - 1) == 0) {
            if (workFactor > 16777215 / resources) {
                throw new IllegalArgumentException("Parameter N is too large");
            } else if (resources > 16777215 / parallelization) {
                throw new IllegalArgumentException("Parameter r is too large");
            }
        } else {
            throw new IllegalArgumentException("N must be a power of 2 greater than 1. Found " + workFactor);
        }
    }

    @Override
    public byte[] scrypt(final byte[] passwd, final byte[] salt, final int dkLen) {
        final byte[] xyArray = new byte[256 * getResources()];
        final byte[] vArray = new byte[128 * getResources() * getWorkFactor()];
        final byte[] intensiveSalt = PBKDF2_HMAC_SHA256_SINGLE_ITERATION_NO_PEPPER.hash(passwd, salt,
                8 * getParallelization() * 128 * getResources());

        for (int i = 0; i < getParallelization(); ++i) {
            sMix(intensiveSalt, i * 128 * getResources(), vArray, xyArray);
        }

        return PBKDF2_HMAC_SHA256_SINGLE_ITERATION_NO_PEPPER.hash(passwd, intensiveSalt, 8 * dkLen);
    }

}
