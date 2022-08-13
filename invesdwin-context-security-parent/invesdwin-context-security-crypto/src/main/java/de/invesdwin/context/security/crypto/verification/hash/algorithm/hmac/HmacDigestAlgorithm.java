package de.invesdwin.context.security.crypto.verification.hash.algorithm.hmac;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceMacHash;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public class HmacDigestAlgorithm implements IHashAlgorithm {
    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int hashSize;

    public HmacDigestAlgorithm(final IHashAlgorithm digestAlgorithm) {
        this(digestAlgorithm.getAlgorithm(), digestAlgorithm.getHashSize());
    }

    public HmacDigestAlgorithm(final String digestAlgorithm, final int hashSize) {
        this.algorithm = "Hmac" + digestAlgorithm;
        this.hashPool = new HashObjectPool(this);
        this.hashSize = hashSize;
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
    public String getKeyAlgorithm() {
        return algorithm;
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Mac;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public int getDefaultKeySize() {
        return getHashSize();
    }

    @Override
    public IHash newHash() {
        return new LazyDelegateHash(new JceMacHash(getAlgorithm()));
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
