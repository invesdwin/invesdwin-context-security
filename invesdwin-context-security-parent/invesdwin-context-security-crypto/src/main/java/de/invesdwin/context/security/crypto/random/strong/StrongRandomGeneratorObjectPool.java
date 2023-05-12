package de.invesdwin.context.security.crypto.random.strong;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.util.concurrent.pool.AAgronaObjectPool;

/**
 * WARNING: prefer to use thread local instance instead of the pool for better performance.
 */
@ThreadSafe
public final class StrongRandomGeneratorObjectPool extends AAgronaObjectPool<StrongRandomGenerator> {

    public static final StrongRandomGeneratorObjectPool INSTANCE = new StrongRandomGeneratorObjectPool();

    private StrongRandomGeneratorObjectPool() {}

    @Override
    protected StrongRandomGenerator newObject() {
        return StrongRandomGenerators.newStrongRandom();
    }

    @Override
    public StrongRandomGenerator borrowObject() {
        final StrongRandomGenerator random = super.borrowObject();
        random.maybeReseed();
        return random;
    }

}
