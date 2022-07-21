package de.invesdwin.context.security.crypto.key.password.argon2.jvm;

import javax.annotation.concurrent.ThreadSafe;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;

import de.invesdwin.util.concurrent.pool.AAgronaObjectPool;

@ThreadSafe
public final class Argon2BytesGeneratorObjectPool extends AAgronaObjectPool<Argon2BytesGenerator> {

    public static final Argon2BytesGeneratorObjectPool INSTANCE = new Argon2BytesGeneratorObjectPool();

    private Argon2BytesGeneratorObjectPool() {
    }

    @Override
    protected Argon2BytesGenerator newObject() {
        return new Argon2BytesGenerator();
    }

}
