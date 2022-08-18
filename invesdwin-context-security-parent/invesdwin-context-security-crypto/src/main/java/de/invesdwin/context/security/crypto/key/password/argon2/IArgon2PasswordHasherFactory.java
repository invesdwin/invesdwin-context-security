package de.invesdwin.context.security.crypto.key.password.argon2;

public interface IArgon2PasswordHasherFactory {

    IArgon2PasswordHasherFactory INSTANCE = IArgon2PasswordHasher.getDefault().getFactory();

    IArgon2PasswordHasher getInstance();

    IArgon2PasswordHasher newInstance(byte[] pepper);

    IArgon2PasswordHasher newInstance(byte[] pepper, Argon2Type type, Argon2Version version, int memory, int iterations,
            int parallelism);

}
