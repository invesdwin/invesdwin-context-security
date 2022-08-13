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
 * DSA is deemed insecure: https://docs.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca5384
 */
@Deprecated
@Immutable
public enum DsaAlgorithm implements ISignatureAlgorithm {
    SHA1withDSA("SHA1withDSA"),
    SHA224withDSA("SHA224withDSA"),
    SHA256withDSA("SHA256withDSA"),
    SHA384withDSA("SHA384withDSA"),
    SHA512withDSA("SHA512withDSA"),
    SHA3_224withDSA("SHA3-224withDSA"),
    SHA3_256withDSA("SHA3-256withDSA"),
    SHA3_384withDSA("SHA3-384withDSA"),
    SHA3_512withDSA("SHA3-512withDSA"),
    /**
     * Deterministic DSA is also insecure.
     */
    SHA1withDDSA("SHA1withDDSA"),
    SHA224withDDSA("SHA224withDDSA"),
    SHA256withDDSA("SHA256withDDSA"),
    SHA384withDDSA("SHA384withDDSA"),
    SHA512withDDSA("SHA512withDDSA"),
    SHA3_224withDDSA("SHA3-224withDDSA"),
    SHA3_256withDDSA("SHA3-256withDDSA"),
    SHA3_384withDDSA("SHA3-384withDDSA"),
    SHA3_512withDDSA("SHA3-512withDDSA"),
    NONEwithDSA("NONEwithDSA");

    public static final DsaAlgorithm DEFAULT = SHA256withDSA;

    private final String algorithm;
    private final HashObjectPool hashPool;

    DsaAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return "DSA";
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return RsaAlgorithm.DEFAULT.getDefaultKeySizeBits();
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
