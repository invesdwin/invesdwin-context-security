package de.invesdwin.context.security.crypto.verification.hash;

import java.security.Key;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;

public interface IHashKey extends IKey {

    IHashAlgorithm getAlgorithm();

    default Key getKey(final HashMode mode) {
        return mode.getKey(this);
    }

    Key getSignKey();

    Key getVerifyKey();

}
