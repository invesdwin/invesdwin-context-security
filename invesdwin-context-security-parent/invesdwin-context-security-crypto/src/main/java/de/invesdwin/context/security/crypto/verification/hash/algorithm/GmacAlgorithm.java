package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SymmetricCipherHashAad;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum GmacAlgorithm implements IHashAlgorithm {
    GMAC_AES_128("GmacAES128", AesKeyLength._128.getBytes()),
    GMAC_AES_196("GmacAES196", AesKeyLength._196.getBytes()),
    GMAC_AES_256("GmacAES256", AesKeyLength._256.getBytes());

    public static final GmacAlgorithm DEFAULT = GMAC_AES_256;

    private static final AesAlgorithm REFERENCE = AesAlgorithm.AES_GCM_NoPadding;
    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int keySize;

    GmacAlgorithm(final String algorithm, final int keySize) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.keySize = keySize;
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
    public int getKeySize() {
        return keySize;
    }

    @Override
    public int getHashSize() {
        return AesKeyLength.BLOCK_SIZE.getBytes();
    }

    @Override
    public IHash newHash() {
        return new SymmetricCipherHashAad(REFERENCE, new CipherCountedIV(REFERENCE));
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return REFERENCE.wrapKey(key);
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
