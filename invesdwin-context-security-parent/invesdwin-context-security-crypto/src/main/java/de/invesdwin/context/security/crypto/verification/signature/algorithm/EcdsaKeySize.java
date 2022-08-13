package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.NotThreadSafe;

@NotThreadSafe
public enum EcdsaKeySize {
    _256(32),
    _384(48),
    //should actually be 521, so maybe give length in bits to DerivedKeyGenerator?
    _512(64);

    public static final EcdsaKeySize DEFAULT = EcdsaKeySize._512;

    private int bytes;
    private int bits;

    EcdsaKeySize(final int bytes) {
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
