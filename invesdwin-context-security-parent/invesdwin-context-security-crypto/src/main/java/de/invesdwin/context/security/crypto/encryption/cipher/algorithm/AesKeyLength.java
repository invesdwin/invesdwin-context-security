package de.invesdwin.context.security.crypto.encryption.cipher.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum AesKeyLength {
    _128(16),
    _196(24),
    _256(32);

    private int bytes;
    private int bits;

    AesKeyLength(final int bytes) {
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