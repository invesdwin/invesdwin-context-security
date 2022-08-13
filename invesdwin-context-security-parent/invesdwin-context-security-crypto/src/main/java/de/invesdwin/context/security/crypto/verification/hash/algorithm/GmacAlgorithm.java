package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeySize;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SymmetricCipherHashAad;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum GmacAlgorithm implements IHashAlgorithm {
    GMAC_AES_128("GmacAES128", AesKeySize._128.getBits()),
    GMAC_AES_196("GmacAES196", AesKeySize._196.getBits()),
    GMAC_AES_256("GmacAES256", AesKeySize._256.getBits());

    public static final GmacAlgorithm DEFAULT = GMAC_AES_256;

    private static final AesAlgorithm REFERENCE = AesAlgorithm.AES_GCM_NoPadding;
    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int keySizeBits;

    GmacAlgorithm(final String algorithm, final int keySizeBits) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.keySizeBits = keySizeBits;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getKeyAlgorithm() {
        return REFERENCE.getKeyAlgorithm();
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Mac;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return keySizeBits;
    }

    @Override
    public int getHashSize() {
        return AesKeySize.BLOCK_SIZE.getBytes();
    }

    @Override
    public IHash newHash() {
        return new SymmetricCipherHashAad(REFERENCE, new CipherCountedIV(REFERENCE));
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
