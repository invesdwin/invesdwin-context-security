package de.invesdwin.context.security.crypto.random;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.util.concurrent.pool.timeout.ATimeoutObjectPool;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@ThreadSafe
public final class CryptoRandomGeneratorObjectPool extends ATimeoutObjectPool<CryptoRandomGenerator> {

    public static final CryptoRandomGeneratorObjectPool INSTANCE = new CryptoRandomGeneratorObjectPool();

    private CryptoRandomGeneratorObjectPool() {
        super(Duration.ONE_MINUTE, new Duration(10, FTimeUnit.SECONDS));
    }

    @Override
    protected CryptoRandomGenerator newObject() {
        return CryptoRandomGenerators.newCryptoRandom();
    }

    @Override
    public void invalidateObject(final CryptoRandomGenerator element) {
        Closeables.closeQuietly(element);
    }

    @Override
    protected void passivateObject(final CryptoRandomGenerator element) {
        //noop
    }

}
