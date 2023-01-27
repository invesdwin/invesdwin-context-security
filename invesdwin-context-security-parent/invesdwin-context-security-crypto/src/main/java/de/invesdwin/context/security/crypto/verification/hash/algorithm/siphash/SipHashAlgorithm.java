package de.invesdwin.context.security.crypto.verification.hash.algorithm.siphash;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://www.bouncycastle.org/specifications.html
 */
@Immutable
public enum SipHashAlgorithm implements IHashAlgorithm {
    SipHash_1_3(new SipHashDigestAlgorithm(1, 3)),
    SipHash_2_4(new SipHashDigestAlgorithm(2, 4)),
    SipHash_4_8(new SipHashDigestAlgorithm(4, 8));

    public static final SipHashAlgorithm DEFAULT = SipHash_2_4;

    private final IHashAlgorithm delegate;

    SipHashAlgorithm(final SipHashDigestAlgorithm delegate) {
        this.delegate = delegate;
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public String getKeyAlgorithm() {
        return delegate.getKeyAlgorithm();
    }

    @Override
    public HashAlgorithmType getType() {
        return delegate.getType();
    }

    @Override
    public int getHashSize() {
        return delegate.getHashSize();
    }

    @Override
    public int getDefaultKeySizeBits() {
        return delegate.getDefaultKeySizeBits();
    }

    @Override
    public IHash newHash() {
        return delegate.newHash();
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return delegate.getHashPool();
    }

}
