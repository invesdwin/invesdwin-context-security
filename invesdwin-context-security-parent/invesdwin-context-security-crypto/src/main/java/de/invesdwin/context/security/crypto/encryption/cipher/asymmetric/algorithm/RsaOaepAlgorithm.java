package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

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
import javax.crypto.spec.OAEPParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipher;

@Immutable
public class RsaOaepAlgorithm implements IAsymmetricCipherAlgorithm {

    public static final RsaOaepAlgorithm DEFAULT = new RsaOaepAlgorithm(OaepPadding.DEFAULT.getCommonParam());

    private final OAEPParameterSpec param;
    private final CipherObjectPool cipherPool;

    public RsaOaepAlgorithm(final OAEPParameterSpec param) {
        this.param = param;
        this.cipherPool = new CipherObjectPool(this);
    }

    @Override
    public ICipher newCipher() {
        try {
            return new JceCipher(Cipher.getInstance(getAlgorithm()), 0);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String toString() {
        return getAlgorithm();
    }

    @Override
    public String getAlgorithm() {
        return "RSA/ECB/OAEPPadding";
    }

    @Override
    public String getKeyAlgorithm() {
        return "RSA";
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

    @Override
    public AlgorithmParameterSpec getParam() {
        return param;
    }

}
