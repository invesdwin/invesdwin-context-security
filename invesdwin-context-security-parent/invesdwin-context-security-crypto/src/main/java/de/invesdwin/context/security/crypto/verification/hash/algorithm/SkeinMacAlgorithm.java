package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceMacHash;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum SkeinMacAlgorithm implements IHashAlgorithm {
    SkeinMac_256_128("Skein-Mac-256-128", DigestAlgorithm.Skein_256_128.getHashSize()),
    SkeinMac_256_160("Skein-Mac-256-160", DigestAlgorithm.Skein_256_160.getHashSize()),
    SkeinMac_256_224("Skein-Mac-256-224", DigestAlgorithm.Skein_256_224.getHashSize()),
    SkeinMac_256_256("Skein-Mac-256-256", DigestAlgorithm.Skein_256_256.getHashSize()),
    SkeinMac_512_128("Skein-Mac-512-128", DigestAlgorithm.Skein_512_128.getHashSize()),
    SkeinMac_512_160("Skein-Mac-512-160", DigestAlgorithm.Skein_512_160.getHashSize()),
    SkeinMac_512_224("Skein-Mac-512-224", DigestAlgorithm.Skein_512_224.getHashSize()),
    SkeinMac_512_256("Skein-Mac-512-256", DigestAlgorithm.Skein_512_256.getHashSize()),
    SkeinMac_512_384("Skein-Mac-512-384", DigestAlgorithm.Skein_512_384.getHashSize()),
    SkeinMac_512_512("Skein-Mac-512-512", DigestAlgorithm.Skein_512_512.getHashSize()),
    SkeinMac_1024_384("Skein-Mac-1024-384", DigestAlgorithm.Skein_1024_384.getHashSize()),
    SkeinMac_1024_512("Skein-Mac-1024-512", DigestAlgorithm.Skein_1024_512.getHashSize()),
    SkeinMac_1024_1024("Skein-Mac-1024-1024", DigestAlgorithm.Skein_1024_1024.getHashSize());

    /**
     * There are many variants of Skein as a cryptographic hash function. They are called Skein_X_Y, where X is internal
     * state size in bits and Y is the output size in bits. The main ones are Skein_512_512, Skein_1024_1024 and
     * Skein_256_256. If you are unsure, then use Skein_512_512.
     * 
     * https://hackage.haskell.org/package/skein-1.0.9.4/docs/Crypto-Skein.html
     */
    public static final SkeinMacAlgorithm DEFAULT = SkeinMac_512_512;

    private final String algorithm;
    private final HashObjectPool hashPool;
    private final int hashSize;

    SkeinMacAlgorithm(final String algorithm, final int hashSize) {
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
    public int getKeySize() {
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
