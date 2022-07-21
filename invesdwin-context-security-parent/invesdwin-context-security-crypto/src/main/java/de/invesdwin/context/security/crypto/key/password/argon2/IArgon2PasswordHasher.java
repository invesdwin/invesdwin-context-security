package de.invesdwin.context.security.crypto.key.password.argon2;

import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.jvm.Argon2PasswordHasher;

public interface IArgon2PasswordHasher extends IPasswordHasher {

    IArgon2PasswordHasher INSTANCE = Argon2PasswordHasher.INSTANCE;

    Argon2Type getType();

    Argon2Version getVersion();

    int getMemory();

    int getIterations();

    int getParallelism();

    IArgon2PasswordHasherFactory getFactory();

}
