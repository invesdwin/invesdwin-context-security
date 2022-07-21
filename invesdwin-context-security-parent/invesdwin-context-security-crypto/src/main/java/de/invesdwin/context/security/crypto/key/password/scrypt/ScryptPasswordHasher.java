package de.invesdwin.context.security.crypto.key.password.scrypt;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;

@Immutable
public class ScryptPasswordHasher implements IPasswordHasher {

    public static final ScryptPasswordHasher INSTANCE = new ScryptPasswordHasher();

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        return null;
    }

}
