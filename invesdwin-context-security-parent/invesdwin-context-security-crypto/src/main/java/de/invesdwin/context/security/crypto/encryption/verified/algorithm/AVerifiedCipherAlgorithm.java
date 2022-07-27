package de.invesdwin.context.security.crypto.encryption.verified.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.verified.VerifiedCipher;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.error.UnknownArgumentException;

@Immutable
public abstract class AVerifiedCipherAlgorithm implements ICipherAlgorithm {

    private final ICipherAlgorithm cipherAlgorithm;
    private final IVerificationFactory verificationFactory;
    private final CipherObjectPool cipherPool;

    protected AVerifiedCipherAlgorithm(final ICipherAlgorithm cipherAlgorithm,
            final IVerificationFactory verificationFactory) {
        Assertions.checkNotNull(cipherAlgorithm);
        Assertions.checkNotNull(verificationFactory);
        this.cipherAlgorithm = cipherAlgorithm;
        this.verificationFactory = verificationFactory;
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
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

    public static AVerifiedCipherAlgorithm wrap(final ICipherAlgorithm algorithm,
            final IVerificationFactory verificationFactory) {
        if (algorithm instanceof ISymmetricCipherAlgorithm) {
            return new VerifiedSymmetricCipherAlgorithm((ISymmetricCipherAlgorithm) algorithm, verificationFactory);
        } else if (algorithm instanceof IAsymmetricCipherAlgorithm) {
            return new VerifiedAsymmetricCipherAlgorithm((IAsymmetricCipherAlgorithm) algorithm, verificationFactory);
        } else {
            throw UnknownArgumentException.newInstance(ICipherAlgorithm.class, algorithm);
        }
    }

}
