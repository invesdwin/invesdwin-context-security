package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm;

import javax.annotation.concurrent.Immutable;

/**
 * https://en.wikipedia.org/wiki/ChaCha20-Poly1305
 */
@Immutable
public enum ChaCha20KeySize {
    _128(128),
    _256(256);

    public static final ChaCha20KeySize BLOCK_SIZE = ChaCha20KeySize._128;

    public static final ChaCha20KeySize DEFAULT = ChaCha20KeySize._256;

    private int bits;

    ChaCha20KeySize(final int bits) {
        this.bits = bits;
    }

    public int getBytes() {
        return bits * Byte.SIZE;
    }

    public int getBits() {
        return bits;
    }

}
