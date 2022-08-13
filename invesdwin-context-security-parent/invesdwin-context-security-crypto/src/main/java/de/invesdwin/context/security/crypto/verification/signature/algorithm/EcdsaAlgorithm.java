package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

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
public enum EcdsaAlgorithm implements ISignatureAlgorithm {
    RIPEMD160withECDSA("RIPEMD160withECDSA"),
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
    SHA512withECNR("SHA512withECNR");

    public static final EcdsaAlgorithm DEFAULT = SHA256withECDDSA;

    private final String algorithm;
    private final HashObjectPool hashPool;

    EcdsaAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return "EC";
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return EcdsaKeySize.DEFAULT.getBits();
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
