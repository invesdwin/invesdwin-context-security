package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.util.zip.Adler32;

import javax.annotation.concurrent.Immutable;

import org.apache.commons.codec.digest.PureJavaCrc32;
import org.apache.commons.codec.digest.PureJavaCrc32C;

import de.invesdwin.context.integration.compression.lz4.LZ4Streams;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.ChecksumHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum ChecksumAlgorithm implements IHashAlgorithm {
    CRC32("CRC32", ChecksumHash.HASH_SIZE) {
        @Override
        public IHash newHash() {
            return new ChecksumHash(getAlgorithm(), new PureJavaCrc32());
        }
    },
    CRC32C("CRC32C", ChecksumHash.HASH_SIZE) {
        @Override
        public IHash newHash() {
            return new ChecksumHash(getAlgorithm(), new PureJavaCrc32C());
        }
    },
    /**
     * Supposed to be almost as good but faster than CRC32.
     */
    Adler32("Adler32", ChecksumHash.HASH_SIZE) {
        @Override
        public IHash newHash() {
            return new ChecksumHash(getAlgorithm(), new Adler32());
        }
    },
    XXHash32("XXHash32", ChecksumHash.HASH_SIZE) {
        @Override
        public IHash newHash() {
            return new ChecksumHash(getAlgorithm(), LZ4Streams.newXXHashFactory().newStreamingHash32(0).asChecksum());
        }
    },
    XXHash64("XXHash64", ChecksumHash.HASH_SIZE) {
        @Override
        public IHash newHash() {
            return new ChecksumHash(getAlgorithm(), LZ4Streams.newXXHashFactory().newStreamingHash64(0).asChecksum());
        }
    };

    public static final ChecksumAlgorithm DEFAULT = XXHash32;
    private final String algorithm;
    private final int hashSize;
    private HashObjectPool hashPool;

    ChecksumAlgorithm(final String algorithm, final int hashSize) {
        this.algorithm = algorithm;
        this.hashSize = hashSize;
        this.hashPool = new HashObjectPool(this);
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
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return getHashSize() * Byte.SIZE;
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Checksum;
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

}
