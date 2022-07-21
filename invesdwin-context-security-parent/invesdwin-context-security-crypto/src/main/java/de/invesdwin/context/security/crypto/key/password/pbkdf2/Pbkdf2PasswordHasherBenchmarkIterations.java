package de.invesdwin.context.security.crypto.key.password.pbkdf2;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;

@NotThreadSafe
public class Pbkdf2PasswordHasherBenchmarkIterations extends APasswordHasherBenchmark<Pbkdf2PasswordHasher> {

    @Override
    public Pbkdf2PasswordHasher getDefaultInstance() {
        return Pbkdf2PasswordHasher.INSTANCE;
    }

    @Override
    public Pbkdf2PasswordHasher newHighMemoryInstance() {
        return getDefaultInstance();
    }

    @Override
    public Pbkdf2PasswordHasher newIterationsInstance(final Pbkdf2PasswordHasher previousInstance,
            final int iterations) {
        return new Pbkdf2PasswordHasher(previousInstance.getPepper(), iterations, previousInstance.getMacAlgorithm());
    }

    @Override
    protected Pbkdf2PasswordHasher newReducedMemoryInstance(final Pbkdf2PasswordHasher previousInstance) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected int increaseIterations(final int iterations) {
        return iterations + getInitialIterations();
    }

    @Override
    protected int getInitialIterations() {
        return 2500;
    }

}
