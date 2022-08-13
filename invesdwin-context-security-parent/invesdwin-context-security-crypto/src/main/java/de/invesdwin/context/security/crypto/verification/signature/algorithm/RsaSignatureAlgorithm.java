package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.context.security.crypto.verification.signature.wrapper.JceSignatureHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://www.bouncycastle.org/specifications.html
 * 
 * https://paretosecurity.com/auditor/checks/ssh-keys-strength
 */
@Immutable
public enum RsaSignatureAlgorithm implements ISignatureAlgorithm {
    MD2withRSA("MD2withRSA"),
    MD5withRSA("MD5withRSA"),
    SHA1withRSA("SHA1withRSA"),
    RIPEMD128withRSA("RIPEMD128withRSA"),
    RIPEMD160withRSA("RIPEMD160withRSA"),
    RIPEMD256withRSA("RIPEMD256withRSA"),
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
    WHIRLPOOLwithRSA_X9_31("WHIRLPOOLwithRSA/X9.31");

    public static final RsaSignatureAlgorithm DEFAULT = SHA256withRSA;

    private final String algorithm;
    private final HashObjectPool hashPool;

    RsaSignatureAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return RsaAlgorithm.DEFAULT.getKeyAlgorithm();
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getDefaultKeySize() {
        return RsaAlgorithm.DEFAULT.getDefaultKeySize();
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
        return new LazyDelegateHash(new JceSignatureHash(algorithm, getHashSize()));
    }

}
