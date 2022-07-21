package de.invesdwin.context.security.crypto.key.password.scrypt;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;

@NotThreadSafe
public class ScryptPasswordHasherBenchmarkResources extends APasswordHasherBenchmark<ScryptPasswordHasher> {

    @Override
    public ScryptPasswordHasher getDefaultInstance() {
        return ScryptPasswordHasher.INSTANCE;
    }

    @Override
    public ScryptPasswordHasher newInitialCostInstance() {
        return getDefaultInstance();
    }

    @Override
    public ScryptPasswordHasher newCostInstance(final ScryptPasswordHasher previousInstance, final int cost) {
        return new ScryptPasswordHasher(previousInstance.getPepper(), new FastScryptFunction(
                previousInstance.getScrypt().getWorkFactor(), cost, previousInstance.getScrypt().getParallelization()));
    }

    @Override
    protected ScryptPasswordHasher newReducedOtherCostInstance(final ScryptPasswordHasher previousInstance) {
        return new ScryptPasswordHasher(previousInstance.getPepper(),
                new FastScryptFunction(previousInstance.getScrypt().getWorkFactor() / 2,
                        previousInstance.getScrypt().getResources(),
                        previousInstance.getScrypt().getParallelization()));
    }

    @Override
    protected String getCostName() {
        return "resources";
    }

    @Override
    protected int increaseCost(final int iterations) {
        return iterations + iterations;
    }

    @Override
    protected int getInitialCost() {
        return 2;
    }

}
