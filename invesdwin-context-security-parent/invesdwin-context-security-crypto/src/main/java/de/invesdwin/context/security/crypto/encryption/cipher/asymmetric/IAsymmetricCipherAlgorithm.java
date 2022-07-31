package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaAlgorithm;

public interface IAsymmetricCipherAlgorithm extends ICipherAlgorithm {

    IAsymmetricCipherAlgorithm DEFAULT = RsaAlgorithm.DEFAULT;

    AlgorithmParameterSpec getParam();

}
