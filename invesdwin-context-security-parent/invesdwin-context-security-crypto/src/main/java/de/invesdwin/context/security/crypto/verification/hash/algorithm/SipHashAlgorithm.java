package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeySize;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.SipHasherStreamHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum SipHashAlgorithm implements IHashAlgorithm {
    SipHash_2_4("SipHash-2-4", 2, 4, Long.BYTES),
    SipHash_4_8("SipHash-4-8", 2, 4, Long.BYTES);

    public static final SipHashAlgorithm DEFAULT = SipHash_2_4;

    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int c;
    private final int d;
    private final int hashSize;

    SipHashAlgorithm(final String algorithm, final int c, final int d, final int hashSize) {
        this.algorithm = algorithm;
        this.hashPool = new HashObjectPool(this);
        this.c = c;
        this.d = d;
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

    public int getC() {
        return c;
    }

    public int getD() {
        return d;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return AesKeySize._128.getBits();
    }

    @Override
    public IHash newHash() {
        return new SipHasherStreamHash(c, d, hashSize);
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
