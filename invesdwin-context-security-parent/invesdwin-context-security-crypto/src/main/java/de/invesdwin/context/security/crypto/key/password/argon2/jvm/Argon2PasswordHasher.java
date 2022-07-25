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
                .add("version", version)
                .add("memory", memory)
                .add("iterations", iterations)
                .add("parallelism", parallelism)
                .toString();
    }

}
