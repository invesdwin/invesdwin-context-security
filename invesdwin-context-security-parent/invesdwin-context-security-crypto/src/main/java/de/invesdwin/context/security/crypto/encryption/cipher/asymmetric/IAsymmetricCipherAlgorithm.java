package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaAlgorithm;

public interface IAsymmetricCipherAlgorithm extends ICipherAlgorithm {

    IAsymmetricCipherAlgorithm DEFAULT = RsaAlgorithm.DEFAULT;

    @Override
    default boolean isSymmetric() {
        return false;
    }

    @Override
    default boolean isAsymmetric() {
        return true;
    }

    PublicKey wrapPublicKey(byte[] publicKey);

    PrivateKey wrapPrivateKey(byte[] privateKey);

    AlgorithmParameterSpec getParam();

}
