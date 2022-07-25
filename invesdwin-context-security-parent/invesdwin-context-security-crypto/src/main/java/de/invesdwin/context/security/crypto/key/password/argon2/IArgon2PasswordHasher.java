package de.invesdwin.context.security.crypto.key.password.argon2;

import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.context.security.crypto.key.password.argon2.unsafe.NativeArgon2PasswordHasherFallback;

public interface IArgon2PasswordHasher extends IPasswordHasher {

    Argon2Type DEFAULT_TYPE = Argon2Type.DEFAULT;
    Argon2Version DEFAULT_VERSION = Argon2Version.DEFAULT;
    /**
     * About 200ms on an I9-900K, this is about 50ms with the native implementation (which uses off-heap memory and
     * actual parallelisation). We calibrate using the single core java implementation and benefit from the better
     * performance of the parallel native implementation (which also only spends the 200ms spread over the given
     * parallel cores).
     * 
     * For high security requirements it would be better to pick the actual cores (multiplied by 2). Then determine with
     * determine the maximum memory (or configure about 64MB or whatever you want to spend) based on 4 iterations. Then
     * find the iterations that suit the time requirements in the parallel native implementation (staying above 4
     * iterations).
     * 
     * Though we follow the guidance from here (at least 12 mb and 20 iterations):
     * https://github.com/Password4j/password4j/wiki/Recommended-settings#argon2
     */
    int DEFAULT_MEMORY = 1 << 14;
    int DEFAULT_ITERATIONS = 20;
    /**
     * Parallelism of 4 is recommended nowadays:
     * https://crypto.stackexchange.com/questions/84081/how-to-choose-parameters-for-argon2-for-a-password-vault
     */
    int DEFAULT_PARALLELISM = 4;

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
