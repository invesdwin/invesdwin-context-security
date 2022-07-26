package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.authenticated.AuthenticatedCipher;
import de.invesdwin.util.assertions.Assertions;

@Immutable
public class AuthenticatedCipherAlgorithm implements ICipherAlgorithm {

    private final ICipherAlgorithm cipherAlgorithm;
    private final IAuthenticationFactory authenticationFactory;
    private final CipherObjectPool cipherPool;

    public AuthenticatedCipherAlgorithm(final ICipherAlgorithm cipherAlgorithm,
            final IAuthenticationFactory authenticationFactory) {
        Assertions.checkNotNull(cipherAlgorithm);
        Assertions.checkNotNull(authenticationFactory);
        this.cipherAlgorithm = cipherAlgorithm;
        this.authenticationFactory = authenticationFactory;
        this.cipherPool = new CipherObjectPool(this);
    }

    public ICipherAlgorithm getCipherAlgorithm() {
        return cipherAlgorithm;
    }

    public IAuthenticationFactory getAuthenticationFactory() {
        return authenticationFactory;
    }

    @Override
    public ICipher newCipher() {
        return new AuthenticatedCipher(cipherAlgorithm.newCipher(), authenticationFactory);
    }

    @Override
    public String getAlgorithm() {
        return cipherAlgorithm.getAlgorithm() + "With" + authenticationFactory.getAlgorithm().getAlgorithm();
    }

    @Override
    public int getBlockSize() {
        return cipherAlgorithm.getBlockSize();
    }

    @Override
    public int getIvSize() {
        return cipherAlgorithm.getIvSize();
    }

    @Override
    public int getSignatureSize() {
        return cipherAlgorithm.getSignatureSize() + authenticationFactory.getAlgorithm().getMacLength();
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
    public AlgorithmParameterSpec wrapIv(final byte[] iv) {
        return cipherAlgorithm.wrapIv(iv);
    }

    @Override
    public AlgorithmParameterSpec wrapIv(final MutableIvParameterSpec iv) {
        return cipherAlgorithm.wrapIv(iv);
    }

}
