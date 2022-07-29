package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SymmetricCipherHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum CmacAlgorithm implements IHashAlgorithm {
    CMAC_AES_128("CmacAES128", AesKeyLength._128.getBytes()),
    CMAC_AES_196("CmacAES196", AesKeyLength._196.getBytes()),
    CMAC_AES_256("CmacAES256", AesKeyLength._256.getBytes());

    public static final CmacAlgorithm DEFAULT = CMAC_AES_256;

    @SuppressWarnings("deprecation")
    private static final AesAlgorithm REFERENCE = AesAlgorithm.AES_CBC_PKCS5Padding;
    private final String algorithm;
    private final HashObjectPool hashPool;
    private int keySize;

    CmacAlgorithm(final String algorithm, final int keySize) {
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
    public int getHashSize() {
        return AesKeyLength.BLOCK_SIZE.getBytes();
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    @Override
    public IHash newHash() {
        return new SymmetricCipherHash(AesAlgorithm.newCryptoCipher("AES/CBC/NoPadding", REFERENCE.getHashSize()),
                new CipherCountedIV(REFERENCE));
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
