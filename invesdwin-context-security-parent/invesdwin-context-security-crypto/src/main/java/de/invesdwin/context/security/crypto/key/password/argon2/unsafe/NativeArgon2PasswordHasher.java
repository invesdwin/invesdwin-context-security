package de.invesdwin.context.security.crypto.key.password.argon2.unsafe;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Type;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Version;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasherFactory;
import de.invesdwin.context.security.crypto.key.password.argon2.jvm.Argon2PasswordHasher;
import de.invesdwin.util.lang.Objects;
import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;

@Immutable
public class NativeArgon2PasswordHasher implements IArgon2PasswordHasher {

    public static final Argon2Type DEFAULT_TYPE = Argon2PasswordHasher.DEFAULT_TYPE;
    public static final Argon2Version DEFAULT_VERSION = Argon2PasswordHasher.DEFAULT_VERSION;
    public static final int DEFAULT_MEMORY = Argon2PasswordHasher.DEFAULT_MEMORY;
    public static final int DEFAULT_ITERATIONS = Argon2PasswordHasher.DEFAULT_ITERATIONS;
    public static final int DEFAULT_PARALLELISM = Argon2PasswordHasher.DEFAULT_PARALLELISM;

    public static final NativeArgon2PasswordHasher INSTANCE = new NativeArgon2PasswordHasher();

    private final byte[] pepper;
    private final Argon2Type type;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final Argon2Version version;
    private final Argon2Advanced argon2;

    private NativeArgon2PasswordHasher() {
        this(CryptoProperties.DEFAULT_PEPPER);
    }

    public NativeArgon2PasswordHasher(final byte[] pepper) {
        this(pepper, DEFAULT_TYPE, DEFAULT_VERSION, DEFAULT_MEMORY, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
    }

    public NativeArgon2PasswordHasher(final byte[] pepper, final Argon2Type type, final Argon2Version version,
            final int memory, final int iterations, final int parallelism) {
        this.pepper = pepper;
        this.type = type;
        this.version = version;
        this.memory = memory;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.argon2 = Argon2Factory.createAdvanced(type.getNativeType());
    }

    @Override
    public IArgon2PasswordHasherFactory getFactory() {
        return NativeArgon2PasswordHasherFactory.INSTANCE;
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
        final byte[] hash = argon2.rawHashAdvanced(iterations, memory, parallelism, password, salt, pepper, null,
                length, version.getNativeVersion());
        return hash;
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
