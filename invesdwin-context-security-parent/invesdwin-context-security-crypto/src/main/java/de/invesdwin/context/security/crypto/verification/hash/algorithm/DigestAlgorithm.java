package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceDigestHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum DigestAlgorithm implements IHashAlgorithm {
    @Deprecated
    MD5("MD5", 16),
    @Deprecated
    SHA_1("SHA1", 20),
    SHA_224("SHA224", 28),
    SHA_256("SHA256", 32),
    SHA_384("SHA384", 48),
    SHA_512("SHA512", 64),
    SHA3_224("SHA3-224", 28),
    SHA3_256("SHA3-256", 32),
    SHA3_384("SHA3-384", 48),
    SHA3_512("SHA3-512", 64),
    RipeMD_128("RipeMD160", 16),
    RipeMD_160("RipeMD160", 20),
    RipeMD_256("RipeMD256", 32),
    RipeMD_320("RipeMD320", 40),
    Whirlpool("Whirlpool", 64);

    /**
     * Intel instructions support up SHA-256 and SHA-1:
     * https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html
     */
    public static final DigestAlgorithm DEFAULT = SHA_256;
    private final String algorithm;
    private final HashObjectPool hashPool;
    private int hashSize;

    DigestAlgorithm(final String algorithm, final int hashSize) {
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
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Digest;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public IHash newHash() {
        return new JceDigestHash(algorithm);
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return new SecretKeySpec(key, algorithm);
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
