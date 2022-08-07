package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;

public interface ISignatureAlgorithm extends IHashAlgorithm {

    ISignatureAlgorithm DEFAULT = AsymmetricCipherSignatureAlgorithm.DEFAULT;

}
