package de.invesdwin.context.security.crypto.verification.hash.algorithm.hmac;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.DigestAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://www.bouncycastle.org/specifications.html
 */
@Immutable
public enum HmacAlgorithm implements IHashAlgorithm {
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    HMAC_MD2(DigestAlgorithm.MD2),
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    HMAC_MD4(DigestAlgorithm.MD4),
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    HMAC_MD5(DigestAlgorithm.MD5),
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    HMAC_SHA_1(DigestAlgorithm.SHA_1),
    HMAC_SHA_224(DigestAlgorithm.SHA_224),
    HMAC_SHA_256(DigestAlgorithm.SHA_256),
    HMAC_SHA_384(DigestAlgorithm.SHA_384),
    HMAC_SHA_512(DigestAlgorithm.SHA_512),
    HMAC_SHA3_224(DigestAlgorithm.SHA3_224),
    HMAC_SHA3_256(DigestAlgorithm.SHA3_256),
    HMAC_SHA3_384(DigestAlgorithm.SHA3_384),
    HMAC_SHA3_512(DigestAlgorithm.SHA3_512),
    HMAC_RipeMD_128(DigestAlgorithm.RipeMD_128),
    HMAC_RipeMD_160(DigestAlgorithm.RipeMD_160),
    HMAC_RipeMD_256(DigestAlgorithm.RipeMD_256),
    HMAC_RipeMD_320(DigestAlgorithm.RipeMD_320),
    HMAC_Whirlpool(DigestAlgorithm.Whirlpool),
    HMAC_Tiger(DigestAlgorithm.Tiger),
    HMAC_GOST3411(DigestAlgorithm.GOST3411),
    HMAC_GOST3411_2012_256(DigestAlgorithm.GOST3411_2012_256),
    HMAC_GOST3411_2012_512(DigestAlgorithm.GOST3411_2012_512),
    HMAC_Keccak_224(new HmacDigestAlgorithm("KECCAK224", 28)),
    HMAC_Keccak_256(new HmacDigestAlgorithm("KECCAK256", 32)),
    HMAC_Keccak_288(new HmacDigestAlgorithm("KECCAK288", 36)),
    HMAC_Keccak_384(new HmacDigestAlgorithm("KECCAK384", 48)),
    HMAC_Keccak_512(new HmacDigestAlgorithm("KECCAK512", 64)),
    HMAC_Skein_256_128(DigestAlgorithm.Skein_256_128),
    HMAC_Skein_256_160(DigestAlgorithm.Skein_256_160),
    HMAC_Skein_256_224(DigestAlgorithm.Skein_256_224),
    HMAC_Skein_256_256(DigestAlgorithm.Skein_256_256),
    HMAC_Skein_512_128(DigestAlgorithm.Skein_512_128),
    HMAC_Skein_512_160(DigestAlgorithm.Skein_512_160),
    HMAC_Skein_512_224(DigestAlgorithm.Skein_512_224),
    HMAC_Skein_512_256(DigestAlgorithm.Skein_512_256),
    HMAC_Skein_512_384(DigestAlgorithm.Skein_512_384),
    HMAC_Skein_512_512(DigestAlgorithm.Skein_512_512),
    HMAC_Skein_1024_384(DigestAlgorithm.Skein_1024_384),
    HMAC_Skein_1024_512(DigestAlgorithm.Skein_1024_512),
    HMAC_Skein_1024_1024(DigestAlgorithm.Skein_1024_1024),
    HMAC_SM3(DigestAlgorithm.SM3),
    HMAC_DSTU7564_256(DigestAlgorithm.DSTU7564_256),
    HMAC_DSTU7564_384(DigestAlgorithm.DSTU7564_384),
    HMAC_DSTU7564_512(DigestAlgorithm.DSTU7564_512);

    public static final HmacAlgorithm DEFAULT = HMAC_SHA_256;

    private final IHashAlgorithm delegate;

    HmacAlgorithm(final IHashAlgorithm delegate) {
        this(new HmacDigestAlgorithm(delegate));
    }

    HmacAlgorithm(final HmacDigestAlgorithm delegate) {
        this.delegate = delegate;
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public HashAlgorithmType getType() {
        return delegate.getType();
    }

    @Override
    public int getHashSize() {
        return delegate.getHashSize();
    }

    @Override
    public int getKeySize() {
        return delegate.getHashSize();
    }

    @Override
    public IHash newHash() {
        return delegate.newHash();
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return delegate.wrapKey(key);
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return delegate.getHashPool();
    }

}
