package de.invesdwin.context.security.crypto.key.password.argon2;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;
import de.invesdwin.context.security.crypto.key.password.argon2.jvm.Argon2PasswordHasher;

@NotThreadSafe
public class Argon2PasswordHasherBenchmarkIterations extends APasswordHasherBenchmark<IArgon2PasswordHasher> {

    @Override
    public IArgon2PasswordHasher getDefaultInstance() {
        return Argon2PasswordHasher.DEFAULT;
    }

    @Override
    public IArgon2PasswordHasher newInitialCostInstance() {
        return getDefaultInstance();
    }

    @Override
    public IArgon2PasswordHasher newCostInstance(final IArgon2PasswordHasher previousInstance, final int cost) {
        return previousInstance.getFactory()
                .newInstance(previousInstance.getPepper(), previousInstance.getType(), previousInstance.getVersion(),
                        previousInstance.getMemory(), cost, previousInstance.getParallelism());
    }

    @Override
    protected IArgon2PasswordHasher newReducedOtherCostInstance(final IArgon2PasswordHasher previousInstance) {
        return previousInstance.getFactory()
                .newInstance(previousInstance.getPepper(), previousInstance.getType(), previousInstance.getVersion(),
                        previousInstance.getMemory() - 1024, previousInstance.getIterations(),
                        previousInstance.getParallelism());
    }

    @Override
    protected String getCostName() {
        return "iterations";
    }

    @Override
    protected int increaseCost(final int cost) {
        return cost + getInitialCost();
    }

    @Override
    protected int getInitialCost() {
        return 2;
    }

}
