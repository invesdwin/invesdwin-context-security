package de.invesdwin.context.security.crypto.key.password.scrypt;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;

@NotThreadSafe
public class ScryptPasswordHasherBenchmarkWorkFactor extends APasswordHasherBenchmark<ScryptPasswordHasher> {

    @Override
    public ScryptPasswordHasher getDefaultInstance() {
        return ScryptPasswordHasher.INSTANCE;
    }

    @Override
    public ScryptPasswordHasher newHighMemoryInstance() {
        return getDefaultInstance();
    }

    @Override
    public ScryptPasswordHasher newIterationsInstance(final ScryptPasswordHasher previousInstance,
            final int iterations) {
        return null;
    }

    @Override
    protected ScryptPasswordHasher newReducedMemoryInstance(final ScryptPasswordHasher previousInstance) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected int increaseIterations(final int iterations) {
        return iterations + 1;
    }

    @Override
    protected int getInitialIterations() {
        return 4;
    }

}
