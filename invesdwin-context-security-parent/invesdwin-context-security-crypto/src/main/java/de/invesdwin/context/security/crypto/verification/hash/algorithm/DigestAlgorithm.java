package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.JceDigestHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://www.bouncycastle.org/specifications.html
 */
@Immutable
public enum DigestAlgorithm implements IHashAlgorithm {
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    MD2("MD2", 16),
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    MD4("MD4", 16),
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
    @Deprecated
    MD5("MD5", 16),
    /**
     * @deprecated deemed insecure or not recommended for new systems
     */
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
    RipeMD_128("RipeMD128", 16),
    RipeMD_160("RipeMD160", 20),
    RipeMD_256("RipeMD256", 32),
    RipeMD_320("RipeMD320", 40),
    Whirlpool("Whirlpool", 64),
    Tiger("Tiger", 24),
    GOST3411("GOST3411", 32),
    GOST3411_2012_256("GOST3411-2012-256", 32),
    GOST3411_2012_512("GOST3411-2012-512", 64),
    Keccak_224("Keccak-224", 28),
    Keccak_256("Keccak-256", 32),
    Keccak_288("Keccak-288", 36),
    Keccak_384("Keccak-384", 48),
    Keccak_512("Keccak-512", 64),
    Skein_256_128("Skein-256-128", 16),
    Skein_256_160("Skein-256-160", 20),
    Skein_256_224("Skein-256-224", 28),
    Skein_256_256("Skein-256-256", 32),
    Skein_512_128("Skein-512-128", 16),
    Skein_512_160("Skein-512-160", 20),
    Skein_512_224("Skein-512-224", 28),
    Skein_512_256("Skein-512-256", 32),
    Skein_512_384("Skein-512-384", 48),
    Skein_512_512("Skein-512-512", 64),
    Skein_1024_384("Skein-1024-384", 48),
    Skein_1024_512("Skein-1024-512", 64),
    Skein_1024_1024("Skein-1024-1024", 128),
    SM3("SM3", 32),
    Blake2b_160("Blake2b-160", 20),
    Blake2b_256("Blake2b-256", 32),
    Blake2b_384("Blake2b-384", 48),
    Blake2b_512("Blake2b-512", 64),
    Blake2s_160("Blake2s-160", 4),
    Blake2s_224("Blake2s-224", 4),
    Blake2s_256("Blake2s-256", 4),
    Blake3_256("Blake3-256", 32),
    DSTU7564_256("DSTU7564-256", 32),
    DSTU7564_384("DSTU7564-384", 48),
    DSTU7564_512("DSTU7564-512", 64),
    SHAKE_128("SHAKE128", 16),
    SHAKE_256("SHAKE256", 32);

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
    public int getKeySize() {
        return getHashSize();
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
