package de.invesdwin.context.security.crypto.key.password.argon2;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;

@Immutable
public class Argon2PasswordHasher implements IPasswordHasher {

    public static final Argon2PasswordHasher INSTANCE = new Argon2PasswordHasher();

    @Override
    public int getIterations() {
        return 0;
    }

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        return null;
    }

}
