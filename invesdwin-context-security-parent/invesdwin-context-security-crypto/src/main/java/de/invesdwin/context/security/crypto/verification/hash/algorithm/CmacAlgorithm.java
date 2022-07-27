package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.aes.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.aes.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.CipherHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@SuppressWarnings("deprecation")
@Immutable
public enum CmacAlgorithm implements IHashAlgorithm {
    CMAC_AES_128(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._128.getBytes()),
    CMAC_AES_196(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._196.getBytes()),
    CMAC_AES_256(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._256.getBytes());

    public static final CmacAlgorithm DEFAULT = CMAC_AES_256;
    private final ICipherAlgorithm algorithm;
    private final HashObjectPool hashPool;
    private int hashSize;

    CmacAlgorithm(final ICipherAlgorithm algorithm, final int hashSize) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.hashSize = hashSize;
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    @Override
    public boolean isAuthentication() {
        return true;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public IHash newHash() {
        return new CipherHash(algorithm, new CipherCountedIV(algorithm));
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return algorithm.wrapKey(key);
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
