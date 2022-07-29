package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

/**
 * RSA requires padding to be secure. Otherwise the same plaintext will be encrypted the same way always.
 * RSA/ECB/NoPadding does not work correctly because the decryption has a too long size because unpadding is missing.
 * 
 * https://crypto.stackexchange.com/questions/3608/why-is-padding-used-for-rsa-encryption-given-that-it-is-not-a-block-cipher
 * 
 * https://github.com/corretto/amazon-corretto-crypto-provider
 */
@Immutable
public final class RsaPkcs1Algorithm extends ARsaAlgorithm {

    public static final RsaPkcs1Algorithm INSTANCE = new RsaPkcs1Algorithm();

    @Override
    public String getAlgorithm() {
        return "RSA/ECB/PKCS1Padding";
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return null;
    }

}
