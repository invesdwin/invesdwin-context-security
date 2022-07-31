package de.invesdwin.context.security.crypto.encryption.verified.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.verified.wrapper.VerifiedCipher;
import de.invesdwin.context.security.crypto.encryption.verified.wrapper.VerifiedCipherObjectPool;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.error.UnknownArgumentException;

@Immutable
public abstract class AVerifiedCipherAlgorithm implements ICipherAlgorithm {

    private final IEncryptionFactory encryptionFactory;
    private final IVerificationFactory verificationFactory;
    private final VerifiedCipherObjectPool cipherPool;

    protected AVerifiedCipherAlgorithm(final IEncryptionFactory encryptionFactory,
            final IVerificationFactory verificationFactory) {
        Assertions.checkNotNull(encryptionFactory);
        Assertions.checkNotNull(verificationFactory);
        this.encryptionFactory = encryptionFactory;
        this.verificationFactory = verificationFactory;
        this.cipherPool = new VerifiedCipherObjectPool(this);
    }

    public IEncryptionFactory getEncryptionFactory() {
        return encryptionFactory;
    }

    public IVerificationFactory getVerificationFactory() {
        return verificationFactory;
    }

    public ICipherAlgorithm getCipherAlgorithm() {
        return encryptionFactory.getAlgorithm();
    }

    public IHashAlgorithm getHashAlgorithm() {
        return verificationFactory.getAlgorithm();
    }

    @Override
    public String getKeyAlgorithm() {
        return getCipherAlgorithm().getKeyAlgorithm();
    }

    @Override
    public int getDefaultKeySize() {
        return getCipherAlgorithm().getDefaultKeySize();
    }

    @Override
    public ICipher newCipher() {
        return new VerifiedCipher(getCipherAlgorithm().newCipher(), getHashAlgorithm().newHash());
    }

    @Override
    public String getAlgorithm() {
        return getCipherAlgorithm().getAlgorithm() + "With" + getHashAlgorithm().getAlgorithm();
    }

    @Override
    public IObjectPool<ICipher> getCipherPool() {
        return cipherPool;
    }

    public static AVerifiedCipherAlgorithm wrap(final IEncryptionFactory encryptionFactory,
            final IVerificationFactory verificationFactory) {
        final ICipherAlgorithm algorithm = encryptionFactory.getAlgorithm();
        if (algorithm instanceof ISymmetricCipherAlgorithm) {
            return new VerifiedSymmetricCipherAlgorithm(encryptionFactory, verificationFactory);
        } else if (algorithm instanceof IAsymmetricCipherAlgorithm) {
            return new VerifiedAsymmetricCipherAlgorithm(encryptionFactory, verificationFactory);
        } else {
            throw UnknownArgumentException.newInstance(ICipherAlgorithm.class, algorithm);
        }
    }

}
