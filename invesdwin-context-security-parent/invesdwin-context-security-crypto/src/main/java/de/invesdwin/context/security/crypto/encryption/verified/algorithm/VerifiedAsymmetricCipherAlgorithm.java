package de.invesdwin.context.security.crypto.encryption.verified.algorithm;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;

@Immutable
public class VerifiedAsymmetricCipherAlgorithm extends AVerifiedCipherAlgorithm implements IAsymmetricCipherAlgorithm {

    public VerifiedAsymmetricCipherAlgorithm(final IEncryptionFactory encryptionFactory,
            final IVerificationFactory verificationFactory) {
        super(encryptionFactory, verificationFactory);
    }

    @Override
    public IAsymmetricCipherAlgorithm getCipherAlgorithm() {
        return (IAsymmetricCipherAlgorithm) super.getCipherAlgorithm();
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return getCipherAlgorithm().getParam();
    }

}
