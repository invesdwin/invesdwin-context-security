package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm;

import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.ChaCha20ParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipherWithKeyBlockSize;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.RefreshingDelegateCipher;

/*
 * PR for XChaCha20 is still pending in BC: https://github.com/bcgit/bc-java/pull/957/files#
 */
@Immutable
public enum ChaCha20Algorithm implements ISymmetricCipherAlgorithm {
    ChaCha20("ChaCha20", 12, 0) {
        @Override
        public AlgorithmParameterSpec wrapParam(final byte[] iv) {
            return new ChaCha20ParameterSpec(iv, 0);
        }

        @Override
        public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
            return wrapParam(iv.getIV());
        }
    };

    public static final ChaCha20Algorithm DEFAULT = ChaCha20;

    private final String algorithm;
    private final int ivSize;
    private final int hashSize;
    private final CipherObjectPool cipherPool;
    private final MutableIvParameterSpecObjectPool ivParameterSpecPool;

    ChaCha20Algorithm(final String algorithm, final int ivSize, final int hashSize) {
        this.algorithm = algorithm;
        this.ivSize = ivSize;
        this.hashSize = hashSize;
        this.cipherPool = new CipherObjectPool(this);
        this.ivParameterSpecPool = new MutableIvParameterSpecObjectPool(ivSize);
    }

    @Override
    public String getKeyAlgorithm() {
        return "ChaCha20";
    }

    /**
     * com.sun.crypto.provider.ChaCha20Cipher does not support 128 bit keys
     */
    @Override
    public int getDefaultKeySizeBits() {
        return AesKeySize._256.getBits();
    }

    @Override
    public String toString() {
        return algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIvSize() {
        return ivSize;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        return ivParameterSpecPool;
    }

    @Override
    public ICipher newCipher() {
        return new RefreshingDelegateCipher(this, new ICipherFactory() {
            @Override
            public ICipher newCipher() {
                try {
                    return new JceCipherWithKeyBlockSize(Cipher.getInstance(algorithm), hashSize);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }
}
