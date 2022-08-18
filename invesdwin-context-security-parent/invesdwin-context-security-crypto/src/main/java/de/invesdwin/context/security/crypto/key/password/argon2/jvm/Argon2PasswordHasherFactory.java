package de.invesdwin.context.security.crypto.key.password.argon2.jvm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Type;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Version;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasherFactory;

@Immutable
public final class Argon2PasswordHasherFactory implements IArgon2PasswordHasherFactory {

    public static final Argon2PasswordHasherFactory INSTANCE = new Argon2PasswordHasherFactory();

    private Argon2PasswordHasherFactory() {
    }

    @Override
    public IArgon2PasswordHasher getInstance() {
        return Argon2PasswordHasher.DEFAULT;
    }

    @Override
    public IArgon2PasswordHasher newInstance(final byte[] pepper) {
        return new Argon2PasswordHasher(pepper);
    }

    @Override
    public IArgon2PasswordHasher newInstance(final byte[] pepper, final Argon2Type type, final Argon2Version version,
            final int memory, final int iterations, final int parallelism) {
        return new Argon2PasswordHasher(pepper, type, version, memory, iterations, parallelism);
    }

}
