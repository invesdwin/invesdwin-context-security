package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceMacHash;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum KmacAlgorithm implements IHashAlgorithm {
    KMAC_128("Kmac128", 16),
    KMAC_256("Kmac256", 32);

    public static final KmacAlgorithm DEFAULT = KMAC_256;

    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int hashSize;

    KmacAlgorithm(final String algorithm, final int hashSize) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.hashSize = hashSize;
    }

    @Override
    public String toString() {
        return algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Mac;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public int getKeySize() {
        return getHashSize();
    }

    @Override
    public IHash newHash() {
        return new LazyDelegateHash(new JceMacHash(getAlgorithm()));
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return new SecretKeySpec(key, algorithm);
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
