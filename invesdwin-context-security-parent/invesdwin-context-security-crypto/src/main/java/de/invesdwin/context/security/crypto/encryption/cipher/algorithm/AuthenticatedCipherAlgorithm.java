package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.AuthenticatedCipher;

@Immutable
public class AuthenticatedCipherAlgorithm implements ICipherAlgorithm {

    private final ICipherAlgorithm delegate;
    private final IAuthenticationFactory authenticationFactory;
    private final CipherObjectPool cipherPool;

    public AuthenticatedCipherAlgorithm(final ICipherAlgorithm delegate,
            final IAuthenticationFactory authenticationFactory) {
        this.delegate = delegate;
        this.authenticationFactory = authenticationFactory;
        this.cipherPool = new CipherObjectPool(this);
    }

    public ICipherAlgorithm getDelegate() {
        return delegate;
    }

    public IAuthenticationFactory getAuthenticationFactory() {
        return authenticationFactory;
    }

    @Override
    public ICipher newCipher() {
        return new AuthenticatedCipher(delegate.newCipher(), authenticationFactory);
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm() + "With" + authenticationFactory.getAlgorithm().getAlgorithm();
    }

    @Override
    public int getBlockSize() {
        return delegate.getBlockSize();
    }

    @Override
    public int getIvSize() {
        return delegate.getIvSize();
    }

    @Override
    public int getSignatureSize() {
        return delegate.getSignatureSize() + authenticationFactory.getAlgorithm().getMacLength();
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        return delegate.getIvParameterSpecPool();
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return delegate.wrapKey(key);
    }

    @Override
    public AlgorithmParameterSpec wrapIv(final byte[] iv) {
        return delegate.wrapIv(iv);
    }

    @Override
    public AlgorithmParameterSpec wrapIv(final MutableIvParameterSpec iv) {
        return delegate.wrapIv(iv);
    }

}
