package de.invesdwin.context.security.crypto.key.password.argon2;

import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.unsafe.NativeArgon2PasswordHasherFallback;

public interface IArgon2PasswordHasher extends IPasswordHasher {

    IArgon2PasswordHasher INSTANCE = NativeArgon2PasswordHasherFallback.INSTANCE;

    @Override
    default String getAlgorithm() {
        return "Argon2";
    }

    Argon2Type getType();

    Argon2Version getVersion();

    int getMemory();

    int getIterations();

    int getParallelism();

    IArgon2PasswordHasherFactory getFactory();

}
