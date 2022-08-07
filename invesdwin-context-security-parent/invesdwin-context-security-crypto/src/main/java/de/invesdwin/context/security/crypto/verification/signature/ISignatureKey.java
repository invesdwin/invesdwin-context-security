package de.invesdwin.context.security.crypto.verification.signature;

import java.security.PrivateKey;
import java.security.PublicKey;

import de.invesdwin.context.security.crypto.verification.hash.IHashKey;
import de.invesdwin.context.security.crypto.verification.signature.algorithm.ISignatureAlgorithm;

public interface ISignatureKey extends IHashKey {

    @Override
    ISignatureAlgorithm getAlgorithm();

    @Override
    PrivateKey getSignKey();

    @Override
    PublicKey getVerifyKey();

}
