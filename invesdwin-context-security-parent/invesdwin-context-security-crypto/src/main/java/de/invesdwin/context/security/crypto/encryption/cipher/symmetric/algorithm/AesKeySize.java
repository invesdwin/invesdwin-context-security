package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum AesKeySize {
    _128(128),
    _192(192),
    _256(256);

    public static final AesKeySize BLOCK_SIZE = AesKeySize._128;

    /**
     * https://www.ubiqsecurity.com/128bit-or-256bit-encryption-which-to-use/
     * 
     * 128 is supposed to be significantly faster than 256
     * 
     * 256 is about 40% slower than 128 according to this: https://security.stackexchange.com/a/19762
     */
    public static final AesKeySize DEFAULT = AesKeySize._128;

    private int bits;

    AesKeySize(final int bits) {
        this.bits = bits;
    }

    public int getBytes() {
        return bits / Byte.SIZE;
    }

    public int getBits() {
        return bits;
    }

}
