package de.invesdwin.context.security.crypto.key.password.argon2.unsafe;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.jvm.Argon2PasswordHasher;

@Immutable
public final class NativeArgon2PasswordHasherFallback {

    public static final IArgon2PasswordHasher INSTANCE;

    static {
        if (NativeArgon2PasswordHasher.AVAILABLE) {
            INSTANCE = NativeArgon2PasswordHasher.INSTANCE;
        } else {
            INSTANCE = Argon2PasswordHasher.INSTANCE;
        }
    }

    private NativeArgon2PasswordHasherFallback() {
    }

}
