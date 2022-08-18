package de.invesdwin.context.security.crypto.random;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.util.concurrent.pool.AAgronaObjectPool;

/**
 * WARNING: prefer to use thread local instance instead of the pool for better performance.
 */
@ThreadSafe
public final class CryptoRandomGeneratorObjectPool extends AAgronaObjectPool<CryptoRandomGenerator> {

    public static final CryptoRandomGeneratorObjectPool INSTANCE = new CryptoRandomGeneratorObjectPool();

    private CryptoRandomGeneratorObjectPool() {}

    @Override
    protected CryptoRandomGenerator newObject() {
        return CryptoRandomGenerators.newCryptoRandom();
    }

    @Override
    public CryptoRandomGenerator borrowObject() {
        final CryptoRandomGenerator random = super.borrowObject();
        random.maybeReseed();
        return random;
    }

    @Override
    public void invalidateObject(final CryptoRandomGenerator element) {
        //noop
    }

    @Override
    protected void passivateObject(final CryptoRandomGenerator element) {
        //noop
    }

}
