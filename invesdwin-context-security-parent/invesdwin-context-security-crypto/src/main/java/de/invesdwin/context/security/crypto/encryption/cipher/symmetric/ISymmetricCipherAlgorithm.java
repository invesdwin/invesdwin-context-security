package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;

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

}
