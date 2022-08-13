package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum DsaKeySize {
    _1024(1024),
    _2048(2048),
    _3072(3072);

    public static final DsaKeySize DEFAULT = _3072;

    private int bits;

    DsaKeySize(final int bits) {
        this.bits = bits;
    }

    public int getBytes() {
        return bits * Byte.SIZE;
    }

    public int getBits() {
        return bits;
    }

}
