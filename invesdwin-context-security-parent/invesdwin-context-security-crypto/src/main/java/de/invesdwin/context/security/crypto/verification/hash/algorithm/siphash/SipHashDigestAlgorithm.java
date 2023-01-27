package de.invesdwin.context.security.crypto.verification.hash.algorithm.siphash;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeySize;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SipHasherStreamHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public class SipHashDigestAlgorithm implements IHashAlgorithm {

    private final HashObjectPool hashPool;
    private final int c;
    private final int d;

    public SipHashDigestAlgorithm(final int c, final int d) {
        this.hashPool = new HashObjectPool(this);
        this.c = c;
        this.d = d;
    }

    @Override
    public String toString() {
        return getAlgorithm();
    }

    @Override
    public String getAlgorithm() {
        return "SipHash-" + c + "-" + d;
    }

    @Override
    public String getKeyAlgorithm() {
        return getAlgorithm();
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Mac;
    }

    public int getC() {
        return c;
    }

    public int getD() {
        return d;
    }

    @Override
    public int getHashSize() {
        return Long.BYTES;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return AesKeySize._128.getBits();
    }

    @Override
    public IHash newHash() {
        return new SipHasherStreamHash(c, d, getHashSize());
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
