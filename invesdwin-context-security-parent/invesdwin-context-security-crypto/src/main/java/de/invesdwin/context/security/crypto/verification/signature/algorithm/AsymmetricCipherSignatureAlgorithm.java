package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.context.security.crypto.verification.signature.wrapper.CipherSignatureHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public class AsymmetricCipherSignatureAlgorithm implements ISignatureAlgorithm {

    public static final AsymmetricCipherSignatureAlgorithm DEFAULT = new AsymmetricCipherSignatureAlgorithm(IHashAlgorithm.DEFAULT,
            IAsymmetricCipherAlgorithm.DEFAULT);

    private final IHashAlgorithm hashAlgorithm;
    private final AsymmetricEncryptionFactory asymmetricEncryptionFactory;
    private final HashObjectPool hashPool;

    public AsymmetricCipherSignatureAlgorithm(final IHashAlgorithm hashAlgorithm,
            final IAsymmetricCipherAlgorithm cipherAlgorithm) {
        this(hashAlgorithm, new AsymmetricEncryptionFactory(cipherAlgorithm, (byte[]) null, (byte[]) null,
                cipherAlgorithm.getDefaultKeySize()));
    }

    public AsymmetricCipherSignatureAlgorithm(final IHashAlgorithm hashAlgorithm,
            final AsymmetricEncryptionFactory asymmetricEncryptionFactory) {
        this.hashAlgorithm = hashAlgorithm;
        this.asymmetricEncryptionFactory = asymmetricEncryptionFactory;
        this.hashPool = new HashObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return asymmetricEncryptionFactory.getAlgorithm().getKeyAlgorithm();
    }

    @Override
    public String getAlgorithm() {
        return hashAlgorithm.getAlgorithm() + "With" + asymmetricEncryptionFactory.getAlgorithm().getAlgorithm();
    }

    @Override
    public int getKeySize() {
        return asymmetricEncryptionFactory.getKey().getKeySize();
    }

    @Override
    public int getHashSize() {
        return hashAlgorithm.getHashSize();
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Signature;
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

    @Override
    public IHash newHash() {
        return new LazyDelegateHash(new CipherSignatureHash(hashAlgorithm.newHash(), asymmetricEncryptionFactory));
    }

}
