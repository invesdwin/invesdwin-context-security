package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaKeySize;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipher;
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
    public int getDefaultKeySizeBits() {
        return RsaKeySize.DEFAULT.getBits();
    }

    @Override
    public ICipher newCipher() {
        return new JceCipherWithKeyBlockSize(JceCipher.getJceCipherInstance(getAlgorithm()), 0);
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

}
