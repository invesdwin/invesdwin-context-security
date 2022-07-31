package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum AesKeySize {
    _128(16),
    _196(24),
    _256(32);

    public static final AesKeySize BLOCK_SIZE = AesKeySize._128;

    public static final AesKeySize DEFAULT = AesKeySize._256;

    private int bytes;
    private int bits;

    AesKeySize(final int bytes) {
        this.bytes = bytes;
        this.bits = bytes * Byte.SIZE;
    }

    public int getBytes() {
        return bytes;
    }

    public int getBits() {
        return bits;
    }

}