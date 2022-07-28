package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.digest.HmacAlgorithms;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceMacHash;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum HmacAlgorithm implements IHashAlgorithm {
    /**
     * @deprecated deemed insecure
     */
    @Deprecated
    HMAC_MD5(HmacAlgorithms.HMAC_MD5.getName(), DigestAlgorithm.MD5.getHashSize()),
    /**
     * @deprecated deemed insecure
     */
    @Deprecated
    HMAC_SHA_1(HmacAlgorithms.HMAC_SHA_1.getName(), DigestAlgorithm.SHA_1.getHashSize()),
    HMAC_SHA_224(HmacAlgorithms.HMAC_SHA_224.getName(), DigestAlgorithm.SHA_224.getHashSize()),
    HMAC_SHA_256(HmacAlgorithms.HMAC_SHA_256.getName(), DigestAlgorithm.SHA_256.getHashSize()),
    HMAC_SHA_384(HmacAlgorithms.HMAC_SHA_384.getName(), DigestAlgorithm.SHA_384.getHashSize()),
    HMAC_SHA_512(HmacAlgorithms.HMAC_SHA_512.getName(), DigestAlgorithm.SHA_512.getHashSize());

    public static final HmacAlgorithm DEFAULT = HMAC_SHA_256;
    private final String algorithm;
    private final HashObjectPool hashPool;
    private int macSize;

    HmacAlgorithm(final String algorithm, final int macSize) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.macSize = macSize;
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
        return macSize;
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
