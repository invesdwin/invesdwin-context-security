package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.stream.StreamingCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.stream.StreamingCipherOutputStream;

public interface ICipherAlgorithm extends ICipherFactory {

    ICipherAlgorithm DEFAULT = AesAlgorithm.DEFAULT;

    @Override
    String getAlgorithm();

    int getBlockSize();

    int getIvSize();

    /**
     * GCM has an encoded signature that is 16 bytes long per encrypted message.
     */
    int getSignatureSize();

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

    CipherObjectPool getCipherPool();

    MutableIvParameterSpecObjectPool getIvParameterSpecPool();

    Key wrapKey(byte[] key);

    AlgorithmParameterSpec wrapIv(byte[] iv);

    AlgorithmParameterSpec wrapIv(MutableIvParameterSpec iv);

}
