package de.invesdwin.context.security.crypto.key.password.argon2.jvm.parallel;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Type;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Version;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasherFactory;

@Immutable
public final class ParallelArgon2PasswordHasherFactory implements IArgon2PasswordHasherFactory {

    public static final ParallelArgon2PasswordHasherFactory INSTANCE = new ParallelArgon2PasswordHasherFactory();

    private ParallelArgon2PasswordHasherFactory() {
    }

    @Override
    public IArgon2PasswordHasher getInstance() {
        return ParallelArgon2PasswordHasher.INSTANCE;
    }

    @Override
    public IArgon2PasswordHasher newInstance(final byte[] pepper) {
        return new ParallelArgon2PasswordHasher(pepper);
    }

    @Override
    public IArgon2PasswordHasher newInstance(final byte[] pepper, final Argon2Type type, final Argon2Version version,
            final int memory, final int iterations, final int parallelism) {
        return new ParallelArgon2PasswordHasher(pepper, type, version, memory, iterations, parallelism);
    }

}
