package de.invesdwin.context.security.crypto.encryption.verified.wrapper;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.verified.algorithm.AVerifiedCipherAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.concurrent.pool.timeout.ATimeoutObjectPool;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@ThreadSafe
public final class VerifiedCipherObjectPool extends ATimeoutObjectPool<ICipher> {

    private final IObjectPool<ICipher> cipherPool;
    private final IObjectPool<IHash> hashPool;

    public VerifiedCipherObjectPool(final AVerifiedCipherAlgorithm algorithm) {
        super(Duration.ONE_MINUTE, new Duration(10, FTimeUnit.SECONDS));
        this.cipherPool = algorithm.getEncryptionFactory().getCipherPool();
        this.hashPool = algorithm.getVerificationFactory().getHashPool();
    }

    @Override
    protected VerifiedCipher newObject() {
        return new VerifiedCipher(null, null);
    }

    @Override
    public synchronized VerifiedCipher borrowObject() {
        final VerifiedCipher element = (VerifiedCipher) super.borrowObject();
        element.setUnverifiedCipher(cipherPool.borrowObject());
        element.setHash(hashPool.borrowObject());
        return element;
    }

    @Override
    public void invalidateObject(final ICipher element) {
        passivateObject(element);
        Closeables.closeQuietly(element);
    }

    @Override
    protected void passivateObject(final ICipher element) {
        final VerifiedCipher cElement = (VerifiedCipher) element;
        cipherPool.returnObject(cElement.getUnverifiedCipher());
        hashPool.returnObject(cElement.getHash());
        cElement.setUnverifiedCipher(null);
        cElement.setHash(null);

    }

}
