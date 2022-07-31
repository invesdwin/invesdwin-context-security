package de.invesdwin.context.security.crypto.encryption.verified.algorithm;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;

@Immutable
public class VerifiedSymmetricCipherAlgorithm extends AVerifiedCipherAlgorithm implements ISymmetricCipherAlgorithm {

    public VerifiedSymmetricCipherAlgorithm(final IEncryptionFactory encryptionFactory,
            final IVerificationFactory verificationFactory) {
        super(encryptionFactory, verificationFactory);
    }

    @Override
    public ISymmetricCipherAlgorithm getCipherAlgorithm() {
        return (ISymmetricCipherAlgorithm) super.getCipherAlgorithm();
    }

    @Override
    public int getIvSize() {
        return getCipherAlgorithm().getIvSize();
    }

    @Override
    public int getHashSize() {
        return getCipherAlgorithm().getHashSize();
    }

    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        return getCipherAlgorithm().getIvParameterSpecPool();
    }

    @Override
    public AlgorithmParameterSpec wrapParam(final byte[] iv) {
        return getCipherAlgorithm().wrapParam(iv);
    }

    @Override
    public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
        return getCipherAlgorithm().wrapParam(iv);
    }

}
