package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipherWithKeyBlockSize;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum EciesAlgorithm implements IAsymmetricCipherAlgorithm {
    ECIESwithSHA1("ECIESwithSHA1"),
    ECIESwithSHA256("ECIESwithSHA256"),
    ECIESwithSHA384("ECIESwithSHA384"),
    ECIESwithSHA512("ECIESwithSHA512"),
    ECIESwithSHA1andAESCBC("ECIESwithSHA1andAES-CBC"),
    ECIESwithSHA1andDESedeCBC("ECIESwithSHA1andDESede-CBC"),
    ECIESwithSHA256andAESCBC("ECIESwithSHA256andAES-CBC"),
    ECIESwithSHA256andDESedeCBC("ECIESwithSHA256andDESede-CBC"),
    ECIESwithSHA384andAESCBC("ECIESwithSHA384andAES-CBC"),
    ECIESwithSHA384andDESedeCBC("ECIESwithSHA384andDESede-CBC"),
    ECIESwithSHA512andAESCBC("ECIESwithSHA512andAES-CBC"),
    ECIESwithSHA512andDESedeCBC("ECIESwithSHA512andDESede-CBC");

    public static final EciesAlgorithm DEFAULT = ECIESwithSHA256;

    private final String algorithm;

    private final CipherObjectPool cipherPool;

    EciesAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.cipherPool = new CipherObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return "ECDH";
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return EciesKeySize.DEFAULT.getBits();
    }

    @Override
    public IObjectPool<ICipher> getCipherPool() {
        return cipherPool;
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
    public AlgorithmParameterSpec getParam() {
        return null;
    }

}
