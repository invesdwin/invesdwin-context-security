package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherPresharedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipher;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SymmetricCipherHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;

@Immutable
public enum CmacAlgorithm implements IHashAlgorithm {
    CMAC_AES_128("CmacAES128", AesKeyLength._128.getBytes()),
    CMAC_AES_196("CmacAES196", AesKeyLength._196.getBytes()),
    CMAC_AES_256("CmacAES256", AesKeyLength._256.getBytes());

    public static final CmacAlgorithm DEFAULT = CMAC_AES_256;

    @SuppressWarnings("deprecation")
    private static final AesAlgorithm REFERENCE = AesAlgorithm.AES_CBC_NoPadding;
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
        try {
            /*
             * Cmac does not require an IV, so we use 0 bytes:
             * https://crypto.stackexchange.com/questions/99508/is-cmac-secure-without-iv-and-the-same-key-authenticate-
             * only
             * 
             * When we use null, com.sun.crypto.provider.CipherCore.init(int, Key, AlgorithmParameterSpec, SecureRandom)
             * will generate a random IV instead which causes hash mismatches
             * 
             * org.bouncycastle.crypto.macs.CMacWithIV says: A non-NIST variant which allows passing of an IV to the
             * underlying CBC cipher. Note: there isn't really a good reason to use an IV here, use the regular CMac
             * where possible.
             */
            return new SymmetricCipherHash(
                    new JceCipher(Cipher.getInstance(REFERENCE.getAlgorithm()), REFERENCE.getHashSize()),
                    new CipherPresharedIV(REFERENCE, ByteBuffers.allocateByteArray(REFERENCE.getIvSize())));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
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
