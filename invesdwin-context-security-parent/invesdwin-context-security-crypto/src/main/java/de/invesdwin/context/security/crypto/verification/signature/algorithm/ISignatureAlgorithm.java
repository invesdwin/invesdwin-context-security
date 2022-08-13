package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.collections.Arrays;

public interface ISignatureAlgorithm extends IHashAlgorithm {

    ISignatureAlgorithm DEFAULT = EddsaAlgorithm.DEFAULT;

    @SuppressWarnings("deprecation")
    static ISignatureAlgorithm[] values() {
        return Arrays.concat(ISignatureAlgorithm.class, DsaAlgorithm.values(), EcdsaAlgorithm.values(),
                EddsaAlgorithm.values(), RsaSignatureAlgorithm.values(), AsymmetricCipherSignatureAlgorithm.values());
    }

}
