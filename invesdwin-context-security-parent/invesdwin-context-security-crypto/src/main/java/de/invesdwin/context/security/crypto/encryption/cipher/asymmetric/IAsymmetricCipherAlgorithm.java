package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaAlgorithm;
import de.invesdwin.util.collections.Arrays;

public interface IAsymmetricCipherAlgorithm extends ICipherAlgorithm {

    static IAsymmetricCipherAlgorithm getDefault() {
        return RsaAlgorithm.DEFAULT;
    }

    static IAsymmetricCipherAlgorithm[] values() {
        return Arrays.concat(IAsymmetricCipherAlgorithm.class, RsaAlgorithm.values());
    }

    AlgorithmParameterSpec getParam();

}
