package de.invesdwin.context.security.crypto.key.password;

public interface IPasswordHasherFactory {

    IPasswordHasher getInstance();

    IPasswordHasher newInstance(byte[] pepper);

}
