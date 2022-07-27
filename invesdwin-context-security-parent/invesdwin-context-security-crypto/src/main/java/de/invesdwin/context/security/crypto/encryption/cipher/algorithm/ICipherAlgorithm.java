package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.aes.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.rsa.RsaAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.stream.StreamingCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.stream.StreamingCipherOutputStream;

public interface ICipherAlgorithm extends ICipherFactory {

    ICipherAlgorithm DEFAULT_SYMMETRIC = AesAlgorithm.DEFAULT;
    ICipherAlgorithm DEFAULT_ASYMMETRIC = RsaAlgorithm.DEFAULT;

    String getKeyAlgorithm();

    /**
     * A symmetric cipher requires a key, an asymmetric cipher requires a public/private key pair.
     */
    boolean isSymmetric();

    /**
     * Requires a public/private key pair.
     */
    default boolean isAsymmetric() {
        return !isSymmetric();
    }

    int getIvSize();

    /**
     * GCM has an encoded signature that is 16 bytes long per encrypted message.
     */
    int getHashSize();

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

    PublicKey wrapPublicKey(byte[] publicKey);

    PrivateKey wrapPrivateKey(byte[] privateKey);

    AlgorithmParameterSpec getParam();

    AlgorithmParameterSpec wrapParam(byte[] iv);

    AlgorithmParameterSpec wrapParam(MutableIvParameterSpec iv);

}
