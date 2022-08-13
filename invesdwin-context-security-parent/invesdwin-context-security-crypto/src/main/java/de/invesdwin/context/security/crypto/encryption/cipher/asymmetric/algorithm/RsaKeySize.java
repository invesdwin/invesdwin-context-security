package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum RsaKeySize {
    _1024(1024),
    _2048(2048),
    _4096(4096);

    /**
     * Intel instructions support up to 4096 key length:
     * https://www.intel.com/content/www/us/en/develop/documentation/ipp-crypto-reference/top/public-key-cryptography-functions/rsa-algorithm-functions.html
     */
    public static final RsaKeySize DEFAULT = _4096;

    private int bits;

    RsaKeySize(final int bits) {
        this.bits = bits;
    }

    public int getBytes() {
        return bits * Byte.SIZE;
    }

    public int getBits() {
        return bits;
    }

}
