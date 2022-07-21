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
    public ScryptPasswordHasher newInitialCostInstance() {
        return getDefaultInstance();
    }

    @Override
    public ScryptPasswordHasher newCostInstance(final ScryptPasswordHasher previousInstance, final int cost) {
        return new ScryptPasswordHasher(previousInstance.getPepper(), new FastScryptFunction(cost,
                previousInstance.getScrypt().getResources(), previousInstance.getScrypt().getParallelization()));
    }

    @Override
    protected ScryptPasswordHasher newReducedOtherCostInstance(final ScryptPasswordHasher previousInstance) {
        return new ScryptPasswordHasher(previousInstance.getPepper(),
                new FastScryptFunction(previousInstance.getScrypt().getWorkFactor(),
                        previousInstance.getScrypt().getResources() / 2,
                        previousInstance.getScrypt().getParallelization()));
    }

    @Override
    protected String getCostName() {
        return "workFactor";
    }

    @Override
    protected int increaseCost(final int cost) {
        return cost + cost;
    }

    @Override
    protected int getInitialCost() {
        return 2;
    }

}
