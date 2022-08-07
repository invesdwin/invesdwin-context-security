package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.DigestAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.context.security.crypto.verification.signature.wrapper.JceSignatureHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum SignatureAlgorithm implements ISignatureAlgorithm {
    DSTU4145("DSTU4145", DigestAlgorithm.SHA_256.getHashSize()),
    Ed25519("Ed25519", DigestAlgorithm.SHA_256.getHashSize()),
    Ed448("Ed448", DigestAlgorithm.SHA_256.getHashSize());

    public static final SignatureAlgorithm DEFAULT = Ed25519;

    private final String algorithm;
    private final int hashSize;
    private final HashObjectPool hashPool;

    SignatureAlgorithm(final String algorithm, final int hashSize) {
        this.algorithm = algorithm;
        this.hashSize = hashSize;
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
        return hashSize;
    }

    @Override
    public int getHashSize() {
        return hashSize;
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
        return new LazyDelegateHash(new JceSignatureHash(algorithm, hashSize));
    }

}
