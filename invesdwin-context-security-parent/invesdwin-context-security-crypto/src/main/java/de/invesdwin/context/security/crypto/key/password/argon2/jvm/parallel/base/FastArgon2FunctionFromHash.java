package de.invesdwin.context.security.crypto.key.password.argon2.jvm.parallel.base;

import javax.annotation.concurrent.Immutable;

@Immutable
public class FastArgon2FunctionFromHash {

    private final FastArgon2Function instance;
    private final int outputLength;

    public FastArgon2FunctionFromHash(final FastArgon2Function instance, final int outputLength) {
        this.instance = instance;
        this.outputLength = outputLength;
    }

    public FastArgon2Function getInstance() {
        return instance;
    }

    public int getOutputLength() {
        return outputLength;
    }

}
