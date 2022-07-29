package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipherWithKeyBlockSize;

/**
 * RSA requires padding to be secure. Otherwise the same plaintext will be encrypted the same way always.
 * RSA/ECB/NoPadding does not work correctly because the decryption has a too long size because unpadding is missing.
 * 
 * https://crypto.stackexchange.com/questions/3608/why-is-padding-used-for-rsa-encryption-given-that-it-is-not-a-block-cipher
 * 
 * https://github.com/corretto/amazon-corretto-crypto-provider
 */
@Immutable
public abstract class ARsaAlgorithm implements IAsymmetricCipherAlgorithm {

    private final CipherObjectPool cipherPool;

    public ARsaAlgorithm() {
        this.cipherPool = new CipherObjectPool(this);
    }

    @Override
    public String toString() {
        return getAlgorithm();
    }

    @Override
    public String getKeyAlgorithm() {
        return "RSA";
    }

    @Override
    public ICipher newCipher() {
        try {
            return new JceCipherWithKeyBlockSize(Cipher.getInstance(getAlgorithm()), 0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
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

}
