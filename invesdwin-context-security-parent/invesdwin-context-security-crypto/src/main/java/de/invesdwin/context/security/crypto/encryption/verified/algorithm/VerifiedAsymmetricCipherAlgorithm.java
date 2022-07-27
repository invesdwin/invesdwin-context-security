package de.invesdwin.context.security.crypto.encryption.verified.algorithm;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;

@Immutable
public class VerifiedAsymmetricCipherAlgorithm extends AVerifiedCipherAlgorithm implements IAsymmetricCipherAlgorithm {

    public VerifiedAsymmetricCipherAlgorithm(final IAsymmetricCipherAlgorithm cipherAlgorithm,
            final IVerificationFactory verificationFactory) {
        super(cipherAlgorithm, verificationFactory);
    }

    @Override
    public IAsymmetricCipherAlgorithm getCipherAlgorithm() {
        return (IAsymmetricCipherAlgorithm) super.getCipherAlgorithm();
    }

    @Override
    public PublicKey wrapPublicKey(final byte[] publicKey) {
        return getCipherAlgorithm().wrapPublicKey(publicKey);
    }

    @Override
    public PrivateKey wrapPrivateKey(final byte[] privateKey) {
        return getCipherAlgorithm().wrapPrivateKey(privateKey);
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return getCipherAlgorithm().getParam();
    }

}
