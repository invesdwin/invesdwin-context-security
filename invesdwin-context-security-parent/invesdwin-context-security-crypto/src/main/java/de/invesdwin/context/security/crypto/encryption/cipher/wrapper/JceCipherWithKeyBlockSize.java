package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

@NotThreadSafe
public class JceCipherWithKeyBlockSize extends JceCipher {

    private Key prevKey;
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
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        if (key != prevKey) {
            blockSize = key.getEncoded().length;
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
