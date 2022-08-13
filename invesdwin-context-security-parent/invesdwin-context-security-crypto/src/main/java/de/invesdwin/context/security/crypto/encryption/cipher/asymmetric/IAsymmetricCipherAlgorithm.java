package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.EciesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaAlgorithm;
import de.invesdwin.util.collections.Arrays;

public interface IAsymmetricCipherAlgorithm extends ICipherAlgorithm {

    /**
     * ECIES should be significantly faster than RSA (similar to EdDSA/EcDSA vs RSA)
     */
    IAsymmetricCipherAlgorithm DEFAULT = EciesAlgorithm.DEFAULT;

    IAsymmetricCipherAlgorithm[] VALUES = Arrays.concat(IAsymmetricCipherAlgorithm.class, RsaAlgorithm.values(),
            EciesAlgorithm.values());

    AlgorithmParameterSpec getParam();

}
