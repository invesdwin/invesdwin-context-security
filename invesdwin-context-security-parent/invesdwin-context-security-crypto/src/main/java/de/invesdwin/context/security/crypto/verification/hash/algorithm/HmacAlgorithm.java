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
public class HmacAlgorithm implements IHashAlgorithm {

    public static final HmacAlgorithm DEFAULT = new HmacAlgorithm(DigestAlgorithm.SHA_256);

    public static final HmacAlgorithm[] VALUES;

    static {
        final DigestAlgorithm[] digests = DigestAlgorithm.values();
        VALUES = new HmacAlgorithm[digests.length];
        for (int i = 0; i < digests.length; i++) {
            VALUES[i] = new HmacAlgorithm(digests[i]);
        }
    }

    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int hashSize;

    public HmacAlgorithm(final IHashAlgorithm digestAlgorithm) {
        this(digestAlgorithm.getAlgorithm(), digestAlgorithm.getHashSize());
    }

    public HmacAlgorithm(final String digestAlgorithm, final int hashSize) {
        this.algorithm = "Hmac" + digestAlgorithm;
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
