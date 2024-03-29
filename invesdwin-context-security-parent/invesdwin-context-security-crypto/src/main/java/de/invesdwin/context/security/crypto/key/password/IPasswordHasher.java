package de.invesdwin.context.security.crypto.key.password;

import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;

/**
 * Only hashes to strengthen and stretch a weak password in order to apply HKDF on it to derive multiple keys.
 * 
 * For encoding passwords for storage, use spring-security-crypto PasswordEncoder instead. It encodes the algorithm
 * parameters in the hash and allows to determine if passwords should be upgraded. NativeArgon2PasswordEncoder provides
 * a fast implementation of Argon2 with a graceful fallback to a JVM instance.
 * 
 * Bcrypt is better than Scrypt (until it is proven, which it is by now) and PBKDF2 (easily cracked by GPUs):
 * https://medium.com/@mpreziuso/password-hashing-pbkdf2-scrypt-bcrypt-1ef4bb9c19b3
 * 
 * Argon2 is better than Scrypt or Bcrypt:
 * https://medium.com/analytics-vidhya/password-hashing-pbkdf2-scrypt-bcrypt-and-argon2-e25aaf41598e
 * 
 * https://github.com/Password4j/password4j/wiki/Recommended-settings#responsiveness-3
 * 
 * Native Argon2 has the benefit of using off-heap memory and being able to utilize parallelization to reduce latency.
 */
public interface IPasswordHasher {

    static IPasswordHasher getDefault() {
        return IArgon2PasswordHasher.getDefault();
    }

    byte[] getPepper();

    String getAlgorithm();

    int getDefaultHashLength();

    byte[] hash(byte[] salt, byte[] password, int length);

}
