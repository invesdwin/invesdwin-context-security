package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingCipherOutputStream;

public interface ISymmetricCipherAlgorithm extends ICipherAlgorithm {

    ISymmetricCipherAlgorithm DEFAULT = AesAlgorithm.DEFAULT;

    @Override
    default boolean isSymmetric() {
        return true;
    }

    @Override
    default boolean isAsymmetric() {
        return false;
    }

    int getIvSize();

    /**
     * GCM has an encoded signature that is 16 bytes long per encrypted message.
     */
    int getHashSize();

    MutableIvParameterSpecObjectPool getIvParameterSpecPool();

    Key wrapKey(byte[] key);

    AlgorithmParameterSpec wrapParam(byte[] iv);

    AlgorithmParameterSpec wrapParam(MutableIvParameterSpec iv);

    default OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final byte[] key, final byte[] iv) {
        try {
            return new StreamingCipherOutputStream(this, out, cipher, key, iv);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    default InputStream newDecryptor(final InputStream in, final ICipher cipher, final byte[] key, final byte[] iv) {
        try {
            return new StreamingCipherInputStream(this, in, cipher, key, iv);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

}
