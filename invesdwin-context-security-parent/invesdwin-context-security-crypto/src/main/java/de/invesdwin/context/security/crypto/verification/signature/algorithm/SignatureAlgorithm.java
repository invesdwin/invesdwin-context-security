package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaKeySize;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.context.security.crypto.verification.signature.wrapper.JceSignatureHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://www.bouncycastle.org/specifications.html
 */
@Immutable
public enum SignatureAlgorithm implements ISignatureAlgorithm {
    DSTU4145("DSTU4145"),
    Ed25519("Ed25519"),
    Ed448("Ed448"),
    GOST3411withGOST3410("GOST3411withGOST3410"),
    GOST3411withECGOST3410("GOST3411withECGOST3410"),
    MD2withRSA("MD2withRSA"),
    MD5withRSA("MD5withRSA"),
    SHA1withRSA("SHA1withRSA"),
    RIPEMD128withRSA("RIPEMD128withRSA"),
    RIPEMD160withRSA("RIPEMD160withRSA"),
    RIPEMD160withDSA("RIPEMD160withDSA"),
    RIPEMD160withECDSA("RIPEMD160withECDSA"),
    RIPEMD256withRSA("RIPEMD256withRSA"),
    SHA1withDSA("SHA1withDSA"),
    SHA224withDSA("SHA224withDSA"),
    SHA256withDSA("SHA256withDSA"),
    SHA384withDSA("SHA384withDSA"),
    SHA512withDSA("SHA512withDSA"),
    SHA3_224withDSA("SHA3-224withDSA"),
    SHA3_256withDSA("SHA3-256withDSA"),
    SHA3_384withDSA("SHA3-384withDSA"),
    SHA3_512withDSA("SHA3-512withDSA"),
    SHA1withDDSA("SHA1withDDSA"),
    SHA224withDDSA("SHA224withDDSA"),
    SHA256withDDSA("SHA256withDDSA"),
    SHA384withDDSA("SHA384withDDSA"),
    SHA512withDDSA("SHA512withDDSA"),
    SHA3_224withDDSA("SHA3-224withDDSA"),
    SHA3_256withDDSA("SHA3-256withDDSA"),
    SHA3_384withDDSA("SHA3-384withDDSA"),
    SHA3_512withDDSA("SHA3-512withDDSA"),
    NONEwithDSA("NONEwithDSA"),
    SHA1withDetECDSA("SHA1withDetECDSA"),
    SHA224withECDDSA("SHA224withECDDSA"),
    SHA256withECDDSA("SHA256withECDDSA"),
    SHA384withECDDSA("SHA384withECDDSA"),
    SHA512withECDDSA("SHA512withECDDSA"),
    SHA1withECDSA("SHA512withECDDSA"),
    NONEwithECDSA("NONEwithECDSA"),
    SHA224withECDSA("SHA224withECDSA"),
    SHA256withECDSA("SHA256withECDSA"),
    SHA384withECDSA("SHA384withECDSA"),
    SHA512withECDSA("SHA512withECDSA"),
    SHA3_224withECDSA("SHA3-224withECDSA"),
    SHA3_256withECDSA("SHA3-256withECDSA"),
    SHA3_384withECDSA("SHA3-384withECDSA"),
    SHA3_512withECDSA("SHA3-512withECDSA"),
    SHAKE128withECDSA("SHAKE128withECDSA"),
    SHAKE256withECDSA("SHAKE256withECDSA"),
    SHA1withPLAIN_ECDSA("SHA1withPLAIN-ECDSA"),
    SHA224withPLAIN_ECDSA("SHA224withPLAIN-ECDSA"),
    SHA256withPLAIN_ECDSA("SHA256withPLAIN-ECDSA"),
    SHA384withPLAIN_ECDSA("SHA384withPLAIN-ECDSA"),
    SHA512withPLAIN_ECDSA("SHA512withPLAIN-ECDSA"),
    SHA3_224withPLAIN_ECDSA("SHA3-224withPLAIN-ECDSA"),
    SHA3_256withPLAIN_ECDSA("SHA3-256withPLAIN-ECDSA"),
    SHA3_384withPLAIN_ECDSA("SHA3-384withPLAIN-ECDSA"),
    SHA3_512withPLAIN_ECDSA("SHA3-512withPLAIN-ECDSA"),
    SHA1withECNR("SHA1withECNR"),
    SHA224withECNR("SHA224withECNR"),
    SHA256withECNR("SHA256withECNR"),
    SHA384withECNR("SHA384withECNR"),
    SHA512withECNR("SHA512withECNR"),
    SHA224withRSA("SHA224withRSA"),
    SHA256withRSA("SHA224withRSA"),
    SHA384withRSA("SHA384withRSA"),
    SHA512withRSA("SHA384withRSA"),
    SHA512_224_withRSA("SHA512(224)withRSA"),
    SHA512_256_withRSA("SHA512(256)withRSA"),
    SHA3_224withRSA("SHA3-224withRSA"),
    SHA3_256withRSA("SHA3-256withRSA"),
    SHA3_384withRSA("SHA3-384withRSA"),
    SHA3_512withRSA("SHA3-512withRSA"),
    SHA1withRSAandMGF1("SHA1withRSAandMGF1"),
    SHA256withRSAandMGF1("SHA256withRSAandMGF1"),
    SHA384withRSAandMGF1("SHA384withRSAandMGF1"),
    SHA512withRSAandMGF1("SHA512withRSAandMGF1"),
    SHA512_224_withRSAandMGF1("SHA512(224)withRSAandMGF1"),
    SHA512_256_withRSAandMGF1("SHA512(256)withRSAandMGF1"),
    SHA1withRSA_ISO9796_2("SHA1withRSA/ISO9796-2"),
    RIPEMD160withRSA_ISO9796_2("RIPEMD160withRSA/ISO9796-2"),
    SHA1withRSA_X9_31("SHA1withRSA/X9.31"),
    SHA224withRSA_X9_31("SHA224withRSA/X9.31"),
    SHA256withRSA_X9_31("SHA256withRSA/X9.31"),
    SHA384withRSA_X9_31("SHA384withRSA/X9.31"),
    SHA512withRSA_X9_31("SHA512withRSA/X9.31"),
    SHA512_224_withRSA_X9_31("SHA512(224)withRSA/X9.31"),
    SHA512_256_withRSA_X9_31("SHA512(256)withRSA/X9.31"),
    RIPEMD128withRSA_X9_31("RIPEMD128withRSA/X9.31"),
    RIPEMD160withRSA_X9_31("RIPEMD160withRSA/X9.31"),
    WHIRLPOOLwithRSA_X9_31("WHIRLPOOLwithRSA/X9.31"),
    SHA512withSPHINCS256("SHA512withSPHINCS256"),
    SHA3_512withSPHINCS256("SHA3-512withSPHINCS256"),
    SHA256withSM2("SHA256withSM2"),
    SM3withSM2("SM3withSM2"),
    LMS("LMS"),
    SPHINCS_PLUS("SPHINCS+"),
    XMSS_SHA256("XMSS-SHA256"),
    XMSS_SHA512("XMSS-SHA512"),
    XMSS_SHAKE128("XMSS-SHAKE128"),
    XMSS_SHAKE256("XMSS-SHAKE256"),
    XMSSMT_SHA256("XMSSMT-SHA256"),
    XMSSMT_SHA512("XMSSMT-SHA512"),
    XMSSMT_SHAKE128("XMSSMT-SHAKE128"),
    XMSSMT_SHAKE256("XMSSMT-SHAKE256"),
    SHA256withXMSS_SHA256("SHA256withXMSS-SHA256"),
    SHA512withXMSS_SHA512("SHA512withXMSS-SHA512"),
    SHAKE128withXMSS_SHAKE128("SHAKE128withXMSS-SHAKE128"),
    SHAKE256withXMSS_SHAKE256("SHAKE256withXMSS-SHAKE256"),
    SHA256withXMSSMT_SHA256("SHA256withXMSSMT-SHA256"),
    SHA512withXMSSMT_SHA512("SHA512withXMSSMT-SHA512"),
    SHAKE128withXMSSMT_SHAKE128("SHAKE128withXMSSMT-SHAKE128"),
    SHAKE256withXMSSMT_SHAKE256("SHAKE256withXMSSMT-SHAKE256"),
    qTESLA_I("qTESLA-I"),
    qTESLA_III_SIZE("qTESLA-III-SIZE"),
    qTESLA_III_SPEED("qTESLA-III-SPEED"),
    qTESLA_P_I("qTESLA-P-I"),
    qTESLA_P_III("qTESLA-P-III");

    public static final SignatureAlgorithm DEFAULT = Ed25519;

    private final String algorithm;
    private final HashObjectPool hashPool;

    SignatureAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return algorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getKeySize() {
        return RsaKeySize.DEFAULT.getBytes();
    }

    @Override
    public int getHashSize() {
        return DYNAMIC_HASH_SIZE;
    }

    @Override
    public boolean isDynamicHashSize() {
        return true;
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Signature;
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

    @Override
    public IHash newHash() {
        return new LazyDelegateHash(new JceSignatureHash(algorithm));
    }

}
