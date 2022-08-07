package de.invesdwin.context.security.crypto.encryption.cipher.hybrid.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper.HybridCipherObjectPool;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public class HybridCipherAlgorithm implements ICipherAlgorithm {

    private final IEncryptionFactory keyEncryptionFactory;
    private final IEncryptionFactory dataEncryptionFactory;
    private final HybridCipherObjectPool cipherPool;

    public HybridCipherAlgorithm(final IEncryptionFactory keyEncryptionFactory,
            final IEncryptionFactory dataEncryptionFactory) {
        this.keyEncryptionFactory = keyEncryptionFactory;
        this.dataEncryptionFactory = dataEncryptionFactory;
        this.cipherPool = new HybridCipherObjectPool(this);
    }

    public IEncryptionFactory getKeyEncryptionFactory() {
        return keyEncryptionFactory;
    }

    public ICipherAlgorithm getKeyCipherAlgorithm() {
        return keyEncryptionFactory.getAlgorithm();
    }

    public IEncryptionFactory getDataEncryptionFactory() {
        return dataEncryptionFactory;
    }

    public ICipherAlgorithm getDataCipherAlgorithm() {
        return dataEncryptionFactory.getAlgorithm();
    }

    @Override
    public String getKeyAlgorithm() {
        return getKeyCipherAlgorithm().getKeyAlgorithm();
    }

    @Override
    public int getDefaultKeySize() {
        return getKeyCipherAlgorithm().getDefaultKeySize();
    }

    @Override
    public ICipher newCipher() {
        return keyEncryptionFactory.getAlgorithm().newCipher();
    }

    @Override
    public String getAlgorithm() {
        return getKeyCipherAlgorithm().getAlgorithm() + " -> " + getDataCipherAlgorithm().getAlgorithm();
    }

    @Override
    public IObjectPool<ICipher> getCipherPool() {
        return cipherPool;
    }

}
