package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding.RsaOaepAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding.RsaPkcs1Algorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;

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

    public static final RsaAlgorithm DEFAULT = RSA_ECB_OAEPPadding;

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
    public int getDefaultKeySizeBits() {
        return delegate.getDefaultKeySizeBits();
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
    public IObjectPool<ICipher> getCipherPool() {
        return delegate.getCipherPool();
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return delegate.getParam();
    }

}
