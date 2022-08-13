package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.NotThreadSafe;

@NotThreadSafe
public enum EcdsaKeySize {
    _256(256),
    _384(384),
    _521(521);

    public static final EcdsaKeySize DEFAULT = EcdsaKeySize._521;

    private int bits;

    EcdsaKeySize(final int bits) {
        this.bits = bits;
    }

    public int getBits() {
        return bits;
    }

}
