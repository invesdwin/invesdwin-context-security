package de.invesdwin.context.security.crypto.key.password.bcrypt;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;

@NotThreadSafe
public class BcryptPasswordHasherBenchmarkLogRounds extends APasswordHasherBenchmark<BcryptPasswordHasher> {

    @Override
    public BcryptPasswordHasher getDefaultInstance() {
        return BcryptPasswordHasher.INSTANCE;
    }

    @Override
    public BcryptPasswordHasher newHighMemoryInstance() {
        return getDefaultInstance();
    }

    @Override
    public BcryptPasswordHasher newIterationsInstance(final BcryptPasswordHasher previousInstance,
            final int iterations) {
        return new BcryptPasswordHasher(previousInstance.getPepper(),
                new RawBcryptFunction(previousInstance.getBcrypt().getType(), iterations));
    }

    @Override
    protected BcryptPasswordHasher newReducedMemoryInstance(final BcryptPasswordHasher previousInstance) {
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
