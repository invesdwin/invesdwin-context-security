package de.invesdwin.context.security.crypto.key.password.argon2;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;

@NotThreadSafe
public class Argon2PasswordHasherBenchmarkMemory extends APasswordHasherBenchmark<IArgon2PasswordHasher> {

    @Override
    public IArgon2PasswordHasher getDefaultInstance() {
        return IArgon2PasswordHasher.getDefault();
    }

    @Override
    public IArgon2PasswordHasher newInitialCostInstance() {
        return getDefaultInstance();
    }

    @Override
    public IArgon2PasswordHasher newCostInstance(final IArgon2PasswordHasher previousInstance, final int cost) {
        return previousInstance.getFactory()
                .newInstance(previousInstance.getPepper(), previousInstance.getType(), previousInstance.getVersion(),
                        cost, previousInstance.getIterations(), previousInstance.getParallelism());
    }

    @Override
    protected IArgon2PasswordHasher newReducedOtherCostInstance(final IArgon2PasswordHasher previousInstance) {
        return previousInstance.getFactory()
                .newInstance(previousInstance.getPepper(), previousInstance.getType(), previousInstance.getVersion(),
                        previousInstance.getMemory() - 1024, previousInstance.getIterations() / 2,
                        previousInstance.getParallelism());
    }

    @Override
    protected String getCostName() {
        return "memory";
    }

    @Override
    protected int increaseCost(final int iterations) {
        return iterations + getInitialCost();
    }

    @Override
    protected int getInitialCost() {
        return 1024; //1KB increment
    }

}
