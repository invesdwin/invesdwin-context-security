package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum RsaKeyLength {
    _1024(128),
    _2048(256),
    _4096(512);

    /**
     * Intel instructions support up to 4096 key length:
     * https://www.intel.com/content/www/us/en/develop/documentation/ipp-crypto-reference/top/public-key-cryptography-functions/rsa-algorithm-functions.html
     */
    public static final RsaKeyLength DEFAULT = _4096;

    private int bytes;
    private int bits;

    RsaKeyLength(final int bytes) {
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
