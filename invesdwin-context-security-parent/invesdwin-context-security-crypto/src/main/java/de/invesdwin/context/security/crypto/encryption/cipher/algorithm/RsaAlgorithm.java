package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipher;

/**
 * https://github.com/corretto/amazon-corretto-crypto-provider
 */
@Immutable
public enum RsaAlgorithm implements ICipherAlgorithm {
    RSA_ECB_NoPadding("RSA/ECB/NoPadding"),
    RSA_ECB_PKCS1Padding("RSA/ECB/PKCS1Padding"),
    RSA_ECB_OAEPPadding("RSA/ECB/OAEPPadding"),
    RSA_ECB_OAEPWithSHA_1AndMGF1Padding("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");

    private String algorithm;

    RsaAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public ICipher newCipher() {
        try {
            return new JceCipher(Cipher.getInstance(getAlgorithm()), getSignatureSize());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getBlockSize() {
        return 0;
    }

    @Override
    public int getIvSize() {
        return 0;
    }

    @Override
    public int getSignatureSize() {
        return 0;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final byte[] key, final byte[] iv) {
        return null;
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final byte[] key, final byte[] iv) {
        return null;
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return new CipherObjectPool(this);
    }

    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        return null;
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return null;
    }

    @Override
    public AlgorithmParameterSpec wrapIv(final byte[] iv) {
        return null;
    }

    @Override
    public AlgorithmParameterSpec wrapIv(final MutableIvParameterSpec iv) {
        return null;
    }

}
