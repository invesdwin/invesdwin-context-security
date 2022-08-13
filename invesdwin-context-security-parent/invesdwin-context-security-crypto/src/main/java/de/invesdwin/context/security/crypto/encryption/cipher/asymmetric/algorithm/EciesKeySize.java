package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum EciesKeySize {
    _192(192),
    _224(224),
    _239(239),
    _256(256),
    _384(384),
    _521(521);

    public static final EciesKeySize DEFAULT = _256;

    private int bits;

    EciesKeySize(final int bits) {
        this.bits = bits;
    }

    public int getBits() {
        return bits;
    }
}
