package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeySize;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceMacHash;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://www.bouncycastle.org/specifications.html
 */
@Immutable
public enum SipHashMacAlgorithm implements IHashAlgorithm {
    SipHash_2_4("SipHash-2-4", Long.BYTES),
    SipHash_4_8("SipHash-4-8", Long.BYTES),
    SipHash128_2_4("SipHash128-2-4", AesKeySize._128.getBytes()),
    SipHash128_4_8("SipHash128-4-8", AesKeySize._128.getBytes());

    public static final SipHashMacAlgorithm DEFAULT = SipHash_2_4;

    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int hashSize;

    SipHashMacAlgorithm(final String algorithm, final int hashSize) {
        this.algorithm = algorithm;
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
    public int getDefaultKeySizeBits() {
        return AesKeySize._128.getBits();
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
