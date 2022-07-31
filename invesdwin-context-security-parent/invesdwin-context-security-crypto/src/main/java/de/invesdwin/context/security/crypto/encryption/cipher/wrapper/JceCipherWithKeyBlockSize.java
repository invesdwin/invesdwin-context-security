package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.key.IKey;

@NotThreadSafe
public class JceCipherWithKeyBlockSize extends JceCipher {

    private IKey prevKey;
    private Integer blockSize;

    public JceCipherWithKeyBlockSize(final Cipher cipher, final int hashSize) {
        super(cipher, hashSize);
    }

    @Override
    public int getBlockSize() {
        if (blockSize == null) {
            throw new IllegalStateException("initialize first");
        }
        return blockSize;
    }

    @Override
    public void init(final CipherMode mode, final IKey key, final AlgorithmParameterSpec params) {
        if (key != prevKey) {
            blockSize = key.getKeySize();
            prevKey = key;
        }
        super.init(mode, key, params);
    }

    @Override
    public void close() {
        prevKey = null;
        blockSize = null;
    }

}
