package de.invesdwin.context.security.crypto.encryption.cipher.algorithm.rsa;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipher;

/**
 * https://github.com/corretto/amazon-corretto-crypto-provider
 */
@Immutable
public enum RsaAlgorithm implements ICipherAlgorithm {
    /**
     * RSA requires padding to be secure. Otherwise the same plaintext will be encrypted the same way always.
     * 
     * https://crypto.stackexchange.com/questions/3608/why-is-padding-used-for-rsa-encryption-given-that-it-is-not-a-block-cipher
     */
    @Deprecated
    RSA_ECB_NoPadding("RSA/ECB/NoPadding"),
    RSA_ECB_PKCS1Padding("RSA/ECB/PKCS1Padding");

    //CHECKSTYLE:OFF
    public static final RsaOaepAlgorithm RSA_ECB_OAEPPadding = RsaOaepAlgorithm.DEFAULT;
    //CHECKSTYLE:ON

    public static final ICipherAlgorithm DEFAULT = RSA_ECB_OAEPPadding;

    private final String algorithm;
    private final CipherObjectPool cipherPool;

    RsaAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.cipherPool = new CipherObjectPool(this);
    }

    @Override
    public String toString() {
        return algorithm;
    }

    @Override
    public String getKeyAlgorithm() {
        return "RSA";
    }

    @Override
    public boolean isSymmetric() {
        return false;
    }

    @Override
    public ICipher newCipher() {
        try {
            return new JceCipher(Cipher.getInstance(getAlgorithm()), getHashSize());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIvSize() {
        return 0;
    }

    @Override
    public int getHashSize() {
        return 0;
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

    @Deprecated
    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        throw new UnsupportedOperationException();
    }

    @Deprecated
    @Override
    public Key wrapKey(final byte[] key) {
        throw new UnsupportedOperationException();
    }

    /**
     * https://stackoverflow.com/questions/19353748/how-to-convert-byte-array-to-privatekey-or-publickey-type
     */
    @Override
    public PrivateKey wrapPrivateKey(final byte[] privateKey) {
        try {
            return KeyFactory.getInstance(getKeyAlgorithm()).generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey wrapPublicKey(final byte[] publicKey) {
        try {
            return KeyFactory.getInstance(getKeyAlgorithm()).generatePublic(new X509EncodedKeySpec(publicKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return null;
    }

    @Deprecated
    @Override
    public AlgorithmParameterSpec wrapParam(final byte[] iv) {
        throw new UnsupportedOperationException();
    }

    @Deprecated
    @Override
    public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
        throw new UnsupportedOperationException();
    }

}
