package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.ChaCha20Algorithm;
import de.invesdwin.util.collections.Arrays;

public interface ISymmetricCipherAlgorithm extends ICipherAlgorithm {

    static ISymmetricCipherAlgorithm getDefault() {
        return AesAlgorithm.DEFAULT;
    }

    @SuppressWarnings("deprecation")
    static ISymmetricCipherAlgorithm[] values() {
        return Arrays.concat(ISymmetricCipherAlgorithm.class,
                Arrays.remove(AesAlgorithm.values(), AesAlgorithm.AES_CBC_NoPadding.ordinal()),
                ChaCha20Algorithm.values());
    }

    int getIvSize();

    /**
     * GCM has an encoded signature that is 16 bytes long per encrypted message.
     */
    int getHashSize();

    MutableIvParameterSpecObjectPool getIvParameterSpecPool();

    AlgorithmParameterSpec wrapParam(byte[] iv);

    AlgorithmParameterSpec wrapParam(MutableIvParameterSpec iv);

}
