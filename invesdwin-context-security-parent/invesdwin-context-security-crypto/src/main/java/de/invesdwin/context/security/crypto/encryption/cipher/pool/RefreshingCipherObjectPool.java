package de.invesdwin.context.security.crypto.encryption.cipher.pool;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.concurrent.pool.AInvalidatingObjectPool;
import de.invesdwin.util.streams.closeable.Closeables;

@ThreadSafe
public final class RefreshingCipherObjectPool extends AInvalidatingObjectPool<ICipher> {

    private final ICipherFactory factory;

    public RefreshingCipherObjectPool(final ICipherFactory factory) {
        this.factory = factory;
    }

    @Override
    protected ICipher newObject() {
        return factory.newCipher();
    }

    @Override
    public void invalidateObject(final ICipher element) {
        Closeables.closeQuietly(element);
    }

}
