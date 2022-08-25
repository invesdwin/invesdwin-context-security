package de.invesdwin.context.security.crypto.key.password.pbkdf2;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.password.APasswordHasherBenchmark;

@NotThreadSafe
public class Pbkdf2PasswordHasherBenchmarkIterations extends APasswordHasherBenchmark<Pbkdf2PasswordHasher> {

    @Override
    public Pbkdf2PasswordHasher getDefaultInstance() {
        return Pbkdf2PasswordHasher.DEFAULT;
    }

    @Override
    public Pbkdf2PasswordHasher newInitialCostInstance() {
        return getDefaultInstance();
    }

    @Override
    public Pbkdf2PasswordHasher newCostInstance(final Pbkdf2PasswordHasher previousInstance, final int iterations) {
        return new Pbkdf2PasswordHasher(previousInstance.getPepper(), iterations, previousInstance.getMacAlgorithm());
    }

    @Override
    protected Pbkdf2PasswordHasher newReducedOtherCostInstance(final Pbkdf2PasswordHasher previousInstance) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected String getCostName() {
        return "iterations";
    }

    @Override
    protected int increaseCost(final int iterations) {
        return iterations + getInitialCost();
    }

    @Override
    protected int getInitialCost() {
        return 2500;
    }

}
