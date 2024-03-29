package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.GCMParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpecObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.JceCipher;

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
 * 
 * AES/ECB should never be used: https://crypto.stackexchange.com/questions/20941/why-shouldnt-i-use-ecb-encryption
 */
@Immutable
public enum AesAlgorithm implements ISymmetricCipherAlgorithm {
    /**
     * CBC will throw exceptions if used without padding. Cmac for example does the padding from the outside.
     */
    @Deprecated
    AES_CBC_NoPadding("AES/CBC/NoPadding", AesKeySize.BLOCK_SIZE.getBytes(), 0) {
        @Override
        public AlgorithmParameterSpec wrapParam(final byte[] iv) {
            return new MutableIvParameterSpec(iv);
        }

        @Override
        public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
            return iv;
        }
    },
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
    AES_CBC_PKCS5Padding("AES/CBC/PKCS5Padding", AesKeySize.BLOCK_SIZE.getBytes(), 0) {
        @Override
        public AlgorithmParameterSpec wrapParam(final byte[] iv) {
            return new MutableIvParameterSpec(iv);
        }

        @Override
        public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
            return iv;
        }
    },
    /**
     * encryption only, streaming capable
     */
    AES_CTR_NoPadding("AES/CTR/NoPadding", AesKeySize.BLOCK_SIZE.getBytes(), 0) {
        @Override
        public AlgorithmParameterSpec wrapParam(final byte[] iv) {
            return new MutableIvParameterSpec(iv);
        }

        @Override
        public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
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
    AES_GCM_NoPadding("AES/GCM/NoPadding", 12, AesKeySize.BLOCK_SIZE.getBytes()) {

        @Override
        public AlgorithmParameterSpec wrapParam(final byte[] iv) {
            return new GCMParameterSpec(AesKeySize.BLOCK_SIZE.getBits(), iv);
        }

        @Override
        public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
            return new GCMParameterSpec(AesKeySize.BLOCK_SIZE.getBits(), iv.getIV());
        }
    };

    public static final AesAlgorithm DEFAULT = AES_CTR_NoPadding;

    private final String algorithm;
    private final int ivSize;
    private final int hashSize;
    private final CipherObjectPool cipherPool;
    private final MutableIvParameterSpecObjectPool ivParameterSpecPool;

    AesAlgorithm(final String algorithm, final int ivSize, final int hashSize) {
        this.algorithm = algorithm;
        this.ivSize = ivSize;
        this.hashSize = hashSize;
        this.cipherPool = new CipherObjectPool(this);
        this.ivParameterSpecPool = new MutableIvParameterSpecObjectPool(ivSize);
    }

    @Override
    public String getKeyAlgorithm() {
        return "AES";
    }

    @Override
    public int getDefaultKeySizeBits() {
        return AesKeySize.DEFAULT.getBits();
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
    public int getIvSize() {
        return ivSize;
    }

    @Override
    public int getHashSize() {
        return hashSize;
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
        return new JceCipher(JceCipher.getJceCipherInstance(algorithm), hashSize);
    }

}
