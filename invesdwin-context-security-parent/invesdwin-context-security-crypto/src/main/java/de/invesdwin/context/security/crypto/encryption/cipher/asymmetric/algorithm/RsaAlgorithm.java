package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding.RsaOaepAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding.RsaPkcs1Algorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;

/**
 * RSA requires padding to be secure. Otherwise the same plaintext will be encrypted the same way always.
 * RSA/ECB/NoPadding does not work correctly because the decryption has a too long size because unpadding is missing.
 * 
 * https://crypto.stackexchange.com/questions/3608/why-is-padding-used-for-rsa-encryption-given-that-it-is-not-a-block-cipher
 * 
 * https://github.com/corretto/amazon-corretto-crypto-provider
 */
@Immutable
public enum RsaAlgorithm implements IAsymmetricCipherAlgorithm {
    RSA_ECB_PKCS1Padding(RsaPkcs1Algorithm.INSTANCE),
    RSA_ECB_OAEPPadding(RsaOaepAlgorithm.DEFAULT);

    private final IAsymmetricCipherAlgorithm delegate;

    RsaAlgorithm(final IAsymmetricCipherAlgorithm delegate) {
        this.delegate = delegate;
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public String getKeyAlgorithm() {
        return delegate.getKeyAlgorithm();
    }

    @Override
    public ICipher newCipher() {
        return delegate.newCipher();
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return delegate.getCipherPool();
    }

    @Override
    public PrivateKey wrapPrivateKey(final byte[] privateKey) {
        return delegate.wrapPrivateKey(privateKey);
    }

    @Override
    public PublicKey wrapPublicKey(final byte[] publicKey) {
        return delegate.wrapPublicKey(publicKey);
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return delegate.getParam();
    }

}