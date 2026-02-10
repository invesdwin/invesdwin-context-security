package de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.hybrid.algorithm.HybridCipherAlgorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.concurrent.pool.timeout.ATimeoutObjectPool;
import de.invesdwin.util.streams.closeable.Closeables;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@ThreadSafe
public final class HybridCipherObjectPool extends ATimeoutObjectPool<ICipher> {

    private final HybridCipherAlgorithm algorithm;
    private final IObjectPool<ICipher> keyCipherPool;
    private final IObjectPool<ICipher> dataCipherPool;

    public HybridCipherObjectPool(final HybridCipherAlgorithm algorithm) {
        super(Duration.ONE_MINUTE, new Duration(10, FTimeUnit.SECONDS));
        this.algorithm = algorithm;
        this.keyCipherPool = algorithm.getKeyEncryptionFactory().getCipherPool();
        this.dataCipherPool = algorithm.getDataEncryptionFactory().getCipherPool();
    }

    @Override
    protected HybridCipher newObject() {
        return new HybridCipher(algorithm.getKeyEncryptionFactory(), algorithm.getDataEncryptionFactory(), null, null);
    }

    @Override
    public synchronized HybridCipher borrowObject() {
        final HybridCipher element = (HybridCipher) super.borrowObject();
        element.setKeyCipher(keyCipherPool.borrowObject());
        element.setDataCipher(dataCipherPool.borrowObject());
        return element;
    }

    @Override
    public void invalidateObject(final ICipher element) {
        passivateObject(element);
        Closeables.closeQuietly(element);
    }

    @Override
    protected boolean passivateObject(final ICipher element) {
        final HybridCipher cElement = (HybridCipher) element;
        keyCipherPool.returnObject(cElement.getKeyCipher());
        dataCipherPool.returnObject(cElement.getDataCipher());
        cElement.setKeyCipher(null);
        cElement.setDataCipher(null);
        return true;

    }

}
