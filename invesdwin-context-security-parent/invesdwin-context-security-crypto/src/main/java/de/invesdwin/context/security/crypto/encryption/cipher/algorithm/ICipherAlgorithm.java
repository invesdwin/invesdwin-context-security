package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;

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

    OutputStream newEncryptor(OutputStream out, byte[] key, byte[] iv);

    InputStream newDecryptor(InputStream in, byte[] key, byte[] iv);

    CipherObjectPool getCipherPool();

    MutableIvParameterSpecObjectPool getIvParameterSpecPool();

    Key wrapKey(byte[] key);

    AlgorithmParameterSpec wrapIv(byte[] iv);

    AlgorithmParameterSpec wrapIv(MutableIvParameterSpec iv);

}
