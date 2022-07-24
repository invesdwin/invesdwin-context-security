package de.invesdwin.context.security.crypto.encryption.cipher.pool;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.concurrent.pool.timeout.ATimeoutObjectPool;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@ThreadSafe
public final class CipherObjectPool extends ATimeoutObjectPool<ICipher> {

    private final ICipherFactory factory;

    public CipherObjectPool(final ICipherFactory factory) {
        super(Duration.ONE_MINUTE, new Duration(10, FTimeUnit.SECONDS));
        this.factory = factory;
    }

    @Override
    protected ICipher newObject() {
        return factory.newCipher();
    }

    @Override
    public void invalidateObject(final ICipher obj) {
        Closeables.closeQuietly(obj);
    }

    @Override
    protected void passivateObject(final ICipher element) {
        //noop
    }

}
