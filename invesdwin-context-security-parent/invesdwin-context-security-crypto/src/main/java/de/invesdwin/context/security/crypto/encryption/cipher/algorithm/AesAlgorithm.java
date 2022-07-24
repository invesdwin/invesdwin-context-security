package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.utils.Utils;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.stream.StreamingCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.stream.StreamingCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.CryptoCipher;
import de.invesdwin.context.system.properties.SystemProperties;

/**
 * https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb
 * 
 * https://crypto.stackexchange.com/questions/48628/why-is-padding-used-in-cbc-mode
 *
 * https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
 * 
 * https://crypto.stackexchange.com/questions/2173/how-to-calculate-an-iv-when-i-have-a-shared-private-key
 * 
 * AES-GCM does authenticated encryption, should be streaming capable but there is no impl in commons-crypto, slower
 * than CTR
 * 
 * https://blog.synopse.info/?post/2021/02/13/Fastest-AES-PRNG%2C-AES-CTR-and-AES-GCM-Delphi-implementation
 * 
 * https://stackoverflow.com/questions/54659935/java-aes-gcm-very-slow-compared-to-aes-ctr
 */
@Immutable
public enum AesAlgorithm implements ICipherAlgorithm {
    /**
     * encryption only, full blocks, not streaming capable
     * 
     * input/output stream can only encrypt/decrypt full file and needs to be closed
     * 
     * @deprecated deemed insecure when not authenticated
     *             https://github.com/corretto/amazon-corretto-crypto-provider/blob/develop/DIFFERENCES.md#aes-gcm-supports-ivparameterspec
     *             https://docs.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode
     */
    @Deprecated
    AES_CBC_PKCS5Padding("AES/CBC/PKCS5Padding", CryptoCipherFactory.AES_BLOCK_SIZE) {
        @Override
        public AlgorithmParameterSpec wrapIv(final byte[] iv) {
            return new MutableIvParameterSpec(iv);
        }

        @Override
        public AlgorithmParameterSpec wrapIv(final MutableIvParameterSpec iv) {
            return iv;
        }
    },
    /**
     * encryption only, streaming capable
     */
    AES_CTR_NoPadding("AES/CTR/NoPadding", CryptoCipherFactory.AES_BLOCK_SIZE) {
        @Override
        public AlgorithmParameterSpec wrapIv(final byte[] iv) {
            return new MutableIvParameterSpec(iv);
        }

        @Override
        public AlgorithmParameterSpec wrapIv(final MutableIvParameterSpec iv) {
            return iv;
        }
    },
    /**
     * authenticated encryption, should be streaming capable but there is no impl in commons-crypto, slower than CTR
     * 
     * https://blog.synopse.info/?post/2021/02/13/Fastest-AES-PRNG%2C-AES-CTR-and-AES-GCM-Delphi-implementation
     * 
     * https://stackoverflow.com/questions/54659935/java-aes-gcm-very-slow-compared-to-aes-ctr
     */
    AES_GCM_NoPadding("AES/GCM/NoPadding", 12) {
        @Override
        public AlgorithmParameterSpec wrapIv(final byte[] iv) {
            return new GCMParameterSpec(AesKeyLength._128.getBits(), iv);
        }

        @Override
        public AlgorithmParameterSpec wrapIv(final MutableIvParameterSpec iv) {
            return new GCMParameterSpec(AesKeyLength._128.getBits(), iv.getIV());
        }
    };

    public static final AesAlgorithm DEFAULT = AES_GCM_NoPadding;

    private final String algorithm;
    private final int ivBytes;
    private final CipherObjectPool cipherPool;
    private final MutableIvParameterSpecObjectPool ivParameterSpecPool;

    AesAlgorithm(final String algorithm, final int ivBytes) {
        this.algorithm = algorithm;
        this.ivBytes = ivBytes;
        this.cipherPool = new CipherObjectPool(this);
        this.ivParameterSpecPool = new MutableIvParameterSpecObjectPool(ivBytes);
    }

    @Override
    public String toString() {
        return algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIvBytes() {
        return ivBytes;
    }

    @Override
    public CipherObjectPool getCipherPool() {
        return cipherPool;
    }

    @Override
    public MutableIvParameterSpecObjectPool getIvParameterSpecPool() {
        return ivParameterSpecPool;
    }

    @Override
    public ICipher newCipher() {
        try {
            return new CryptoCipher(Utils.getCipherInstance(getAlgorithm(), SystemProperties.SYSTEM_PROPERTIES));
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final byte[] key, final byte[] iv) {
        try {
            return new StreamingCipherOutputStream(this, out, key, iv);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final byte[] key, final byte[] iv) {
        try {
            return new StreamingCipherInputStream(this, in, key, iv);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

}
