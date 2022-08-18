package de.invesdwin.context.security.crypto.key.password.argon2.unsafe;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.jvm.Argon2PasswordHasher;

@Immutable
public final class NativeArgon2PasswordHasherFallback {

    public static final IArgon2PasswordHasher DEFAULT;

    static {
        if (NativeArgon2PasswordHasher.AVAILABLE) {
            DEFAULT = NativeArgon2PasswordHasher.DEFAULT;
        } else {
            DEFAULT = Argon2PasswordHasher.DEFAULT;
        }
    }

    private NativeArgon2PasswordHasherFallback() {
    }

}
