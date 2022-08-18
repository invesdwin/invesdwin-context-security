package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.DigestAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.context.security.crypto.verification.signature.wrapper.CipherSignatureHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public class AsymmetricCipherSignatureAlgorithm implements ISignatureAlgorithm {

    public static final AsymmetricCipherSignatureAlgorithm DEFAULT = new AsymmetricCipherSignatureAlgorithm(
            //no need to use HMAC_SHA_256, since RSA already provides the integrity and authentication in addition to the non-repudiation
            DigestAlgorithm.SHA_256, IAsymmetricCipherAlgorithm.getDefault());

    private final IHashAlgorithm hashAlgorithm;
    private final AsymmetricEncryptionFactory asymmetricEncryptionFactory;
    private final HashObjectPool hashPool;

    public AsymmetricCipherSignatureAlgorithm(final IHashAlgorithm hashAlgorithm,
            final IAsymmetricCipherAlgorithm cipherAlgorithm) {
        this(hashAlgorithm, new AsymmetricEncryptionFactory(cipherAlgorithm, (byte[]) null, (byte[]) null,
                cipherAlgorithm.getDefaultKeySizeBits()));
    }

    public AsymmetricCipherSignatureAlgorithm(final IHashAlgorithm hashAlgorithm,
            final AsymmetricEncryptionFactory asymmetricEncryptionFactory) {
        this.hashAlgorithm = hashAlgorithm;
        this.asymmetricEncryptionFactory = asymmetricEncryptionFactory;
        this.hashPool = new HashObjectPool(this);
    }

    public static AsymmetricCipherSignatureAlgorithm[] values() {
        final List<AsymmetricCipherSignatureAlgorithm> values = new ArrayList<>();
        for (final IAsymmetricCipherAlgorithm asymmetricAlgorithm : IAsymmetricCipherAlgorithm.values()) {
            for (final IHashAlgorithm hashAlgorithm : IHashAlgorithm.values()) {
                values.add(new AsymmetricCipherSignatureAlgorithm(hashAlgorithm, asymmetricAlgorithm));
            }
        }
        return values.toArray(new AsymmetricCipherSignatureAlgorithm[0]);
    }

    @Override
    public String getKeyAlgorithm() {
        return asymmetricEncryptionFactory.getAlgorithm().getKeyAlgorithm();
    }

    @Override
    public String getAlgorithm() {
        return hashAlgorithm.getAlgorithm() + " with " + asymmetricEncryptionFactory.getAlgorithm().getAlgorithm();
    }

    @Override
    public int getDefaultKeySizeBits() {
        return asymmetricEncryptionFactory.getKey().getKeySizeBits();
    }

    @Override
    public int getHashSize() {
        return DYNAMIC_HASH_SIZE;
    }

    @Override
    public boolean isDynamicHashSize() {
        return true;
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
        return new LazyDelegateHash(new CipherSignatureHash(hashAlgorithm, asymmetricEncryptionFactory));
    }

}
