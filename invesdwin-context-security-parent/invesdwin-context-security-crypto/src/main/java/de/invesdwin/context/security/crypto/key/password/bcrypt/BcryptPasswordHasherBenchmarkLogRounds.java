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
    public BcryptPasswordHasher newInitialCostInstance() {
        return getDefaultInstance();
    }

    @Override
    public BcryptPasswordHasher newCostInstance(final BcryptPasswordHasher previousInstance, final int iterations) {
        return new BcryptPasswordHasher(previousInstance.getPepper(),
                new RawBcryptFunction(previousInstance.getBcrypt().getType(), iterations));
    }

    @Override
    protected BcryptPasswordHasher newReducedOtherCostInstance(final BcryptPasswordHasher previousInstance) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected String getCostName() {
        return "logRounds";
    }

    @Override
    protected int increaseCost(final int iterations) {
        return iterations + 1;
    }

    @Override
    protected int getInitialCost() {
        return 4;
    }

}
