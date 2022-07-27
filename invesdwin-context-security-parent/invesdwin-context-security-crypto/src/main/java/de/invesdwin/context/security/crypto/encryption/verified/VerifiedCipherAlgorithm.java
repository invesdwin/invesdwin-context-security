package de.invesdwin.context.security.crypto.encryption.verified;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.util.assertions.Assertions;

@Immutable
public class VerifiedCipherAlgorithm implements ICipherAlgorithm {

    private final ICipherAlgorithm cipherAlgorithm;
    private final IVerificationFactory verificationFactory;
    private final CipherObjectPool cipherPool;

    public VerifiedCipherAlgorithm(final ICipherAlgorithm cipherAlgorithm,
            final IVerificationFactory authenticationFactory) {
        Assertions.checkNotNull(cipherAlgorithm);
        Assertions.checkNotNull(authenticationFactory);
        this.cipherAlgorithm = cipherAlgorithm;
        this.verificationFactory = authenticationFactory;
        this.cipherPool = new CipherObjectPool(this);
    }

    public ICipherAlgorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    @Override
    public String getKeyAlgorithm() {
        return cipherAlgorithm.getKeyAlgorithm();
    }

    @Override
    public boolean isSymmetric() {
        return cipherAlgorithm.isSymmetric();
    }

    @Override
    public boolean isAsymmetric() {
        return cipherAlgorithm.isAsymmetric();
    }

    public IVerificationFactory getVerificationFactory() {
        return verificationFactory;
    }

    @Override
    public ICipher newCipher() {
        return new VerifiedCipher(cipherAlgorithm.newCipher(), verificationFactory);
    }

    @Override
    public String getAlgorithm() {
        return cipherAlgorithm.getAlgorithm() + "With" + verificationFactory.getAlgorithm().getAlgorithm();
    }

    @Override
    public int getIvSize() {
        return cipherAlgorithm.getIvSize();
    }

    @Override
    public int getHashSize() {
        return cipherAlgorithm.getHashSize() + verificationFactory.getAlgorithm().getHashSize();
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        return cipherAlgorithm.getIvParameterSpecPool();
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return cipherAlgorithm.wrapKey(key);
    }

    @Override
    public AlgorithmParameterSpec wrapParam(final byte[] iv) {
        return cipherAlgorithm.wrapParam(iv);
    }

    @Override
    public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
        return cipherAlgorithm.wrapParam(iv);
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return cipherAlgorithm.getParam();
    }

    @Override
    public PublicKey wrapPublicKey(final byte[] publicKey) {
        return cipherAlgorithm.wrapPublicKey(publicKey);
    }

    @Override
    public PrivateKey wrapPrivateKey(final byte[] privateKey) {
        return cipherAlgorithm.wrapPrivateKey(privateKey);
    }

}
