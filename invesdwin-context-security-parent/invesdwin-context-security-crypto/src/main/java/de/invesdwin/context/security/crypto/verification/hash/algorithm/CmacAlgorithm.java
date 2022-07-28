package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SymmetricCipherHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@SuppressWarnings("deprecation")
@Immutable
public enum CmacAlgorithm implements IHashAlgorithm {
    CMAC_AES_128(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._128.getBytes()),
    CMAC_AES_196(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._196.getBytes()),
    CMAC_AES_256(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._256.getBytes());

    public static final CmacAlgorithm DEFAULT = CMAC_AES_256;
    private final ISymmetricCipherAlgorithm algorithm;
    private final HashObjectPool hashPool;
    private int hashSize;

    CmacAlgorithm(final ISymmetricCipherAlgorithm algorithm, final int hashSize) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.hashSize = hashSize;
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
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
    public IHash newHash() {
        return new SymmetricCipherHash(algorithm, new CipherCountedIV(algorithm));
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
