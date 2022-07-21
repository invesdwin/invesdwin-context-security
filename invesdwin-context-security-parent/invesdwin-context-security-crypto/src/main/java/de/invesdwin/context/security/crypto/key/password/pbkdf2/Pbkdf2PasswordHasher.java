package de.invesdwin.context.security.crypto.key.password.pbkdf2;

import java.security.spec.InvalidKeySpecException;

import javax.annotation.concurrent.Immutable;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.authentication.mac.IMacAlgorithm;
import de.invesdwin.context.security.crypto.authentication.mac.hmac.HmacAlgorithm;
import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.math.Bytes;

/**
 * Adapted from: org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
 * 
 * A java implementation of https://github.com/ctz/fastpbkdf2 would be nice, though native Argon2 is still better due to
 * parallelization and general higher security of the algorithm.
 */
@Immutable
public class Pbkdf2PasswordHasher implements IPasswordHasher {

    public static final String ALGORITHM_PREFIX = "PBKDF2With";
    /**
     * About 200ms on an I9-9900k
     */
    public static final int DEFAULT_ITERATIONS = 200_000;
    public static final IMacAlgorithm DEFAULT_MAC_ALGORITHM = HmacAlgorithm.HMAC_SHA_512;
    public static final Pbkdf2PasswordHasher INSTANCE = new Pbkdf2PasswordHasher();

    private final int iterations;
    private final byte[] pepper;
    private final IMacAlgorithm macAlgorithm;
    private final String algorithm;
    private final SecretKeyFactoryObjectPool secretKeyFactoryPool;

    private Pbkdf2PasswordHasher() {
        this(CryptoProperties.DEFAULT_PEPPER);
    }

    public Pbkdf2PasswordHasher(final byte[] pepper) {
        this(pepper, DEFAULT_ITERATIONS);
    }

    public Pbkdf2PasswordHasher(final byte[] pepper, final int iterations) {
        this(pepper, iterations, DEFAULT_MAC_ALGORITHM);
    }

    public Pbkdf2PasswordHasher(final byte[] pepper, final int iterations, final IMacAlgorithm macAlgorithm) {
        this.pepper = pepper;
        this.iterations = iterations;
        this.macAlgorithm = macAlgorithm;
        this.algorithm = ALGORITHM_PREFIX + macAlgorithm.getAlgorithm();
        this.secretKeyFactoryPool = new SecretKeyFactoryObjectPool(algorithm);
    }

    public int getIterations() {
        return iterations;
    }

    @Override
    public byte[] getPepper() {
        return pepper;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public IMacAlgorithm getMacAlgorithm() {
        return macAlgorithm;
    }

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        final PBEKeySpec spec = new PBEKeySpec(new String(password).toCharArray(), Bytes.concat(salt, this.pepper),
                this.iterations, length);
        final SecretKeyFactory secretKeyFactory = secretKeyFactoryPool.borrowObject();
        try {
            return secretKeyFactory.generateSecret(spec).getEncoded();
        } catch (final InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            secretKeyFactoryPool.returnObject(secretKeyFactory);
        }
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this).add("algorithm", algorithm).add("iterations", iterations).toString();
    }

}
