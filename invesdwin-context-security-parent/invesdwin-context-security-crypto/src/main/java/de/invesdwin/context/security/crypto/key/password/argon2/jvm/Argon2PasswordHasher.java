package de.invesdwin.context.security.crypto.key.password.argon2.jvm;

import javax.annotation.concurrent.Immutable;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Type;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Version;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasherFactory;
import de.invesdwin.util.lang.Objects;

@Immutable
public class Argon2PasswordHasher implements IArgon2PasswordHasher {

    public static final Argon2Type DEFAULT_TYPE = Argon2Type.DEFAULT;
    public static final Argon2Version DEFAULT_VERSION = Argon2Version.DEFAULT;
    /**
     * About 200ms on an I9-900K, this is about 50ms with the native implementation (which uses off-heap memory and
     * actual parallelisation). We calibrate using the single core java implementation and benefit from the better
     * performance of the parallel native implementation (which also only spends the 200ms spread over the given
     * parallel cores).
     * 
     * For high security requirements it would be better to pick the actual cores (multiplied by 2). Then determine with
     * determine the maximum memory (or configure about 64MB or whatever you want to spend) based on 4 iterations. Then
     * find the iterations that suit the time requirements in the parallel native implementation (staying above 4
     * iterations).
     * 
     * Though we follow the guidance from here (at least 12 mb and 20 iterations):
     * https://github.com/Password4j/password4j/wiki/Recommended-settings#argon2
     */
    public static final int DEFAULT_MEMORY = 1 << 14;
    public static final int DEFAULT_ITERATIONS = 20;
    /**
     * Parallelism of 4 is recommended nowadays:
     * https://crypto.stackexchange.com/questions/84081/how-to-choose-parameters-for-argon2-for-a-password-vault
     */
    public static final int DEFAULT_PARALLELISM = 4;

    public static final Argon2PasswordHasher INSTANCE = new Argon2PasswordHasher();

    private final byte[] pepper;
    private final Argon2Type type;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final Argon2Version version;

    private Argon2PasswordHasher() {
        this(CryptoProperties.DEFAULT_PEPPER);
    }

    public Argon2PasswordHasher(final byte[] pepper) {
        this(pepper, DEFAULT_TYPE, DEFAULT_VERSION, DEFAULT_MEMORY, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
    }

    public Argon2PasswordHasher(final byte[] pepper, final Argon2Type type, final Argon2Version version,
            final int memory, final int iterations, final int parallelism) {
        this.pepper = pepper;
        this.type = type;
        this.version = version;
        this.memory = memory;
        this.iterations = iterations;
        this.parallelism = parallelism;
    }

    @Override
    public IArgon2PasswordHasherFactory getFactory() {
        return Argon2PasswordHasherFactory.INSTANCE;
    }

    @Override
    public byte[] getPepper() {
        return pepper;
    }

    @Override
    public Argon2Type getType() {
        return type;
    }

    @Override
    public Argon2Version getVersion() {
        return version;
    }

    @Override
    public int getMemory() {
        return memory;
    }

    @Override
    public int getIterations() {
        return iterations;
    }

    @Override
    public int getParallelism() {
        return parallelism;
    }

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        final Argon2Parameters params = new Argon2Parameters.Builder(this.type.getType()).withSalt(salt)
                .withVersion(this.version.getVersion())
                .withParallelism(this.parallelism)
                .withMemoryAsKB(this.memory)
                .withIterations(this.iterations)
                .withSecret(this.pepper)
                .build();
        final Argon2BytesGenerator generator = Argon2BytesGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            generator.init(params);
            final byte[] hash = new byte[length];
            generator.generateBytes(password, hash);
            return hash;
        } finally {
            Argon2BytesGeneratorObjectPool.INSTANCE.returnObject(generator);
        }
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                .add("type", type)
                .add("memory", memory)
                .add("iterations", iterations)
                .add("parallelism", parallelism)
                .add("version", version)
                .toString();
    }

}
