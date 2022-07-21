package de.invesdwin.context.security.crypto.key.password.argon2.unsafe;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Type;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Version;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasherFactory;

@Immutable
public final class NativeArgon2PasswordHasherFactory implements IArgon2PasswordHasherFactory {

    public static final NativeArgon2PasswordHasherFactory INSTANCE = new NativeArgon2PasswordHasherFactory();

    private NativeArgon2PasswordHasherFactory() {
    }

    @Override
    public IArgon2PasswordHasher getInstance() {
        return NativeArgon2PasswordHasher.INSTANCE;
    }

    @Override
    public IArgon2PasswordHasher newInstance(final byte[] pepper) {
        return new NativeArgon2PasswordHasher(pepper);
    }

    @Override
    public IArgon2PasswordHasher newInstance(final byte[] pepper, final Argon2Type type, final Argon2Version version,
            final int memory, final int iterations, final int parallelism) {
        return new NativeArgon2PasswordHasher(pepper, type, version, memory, iterations, parallelism);
    }

}
