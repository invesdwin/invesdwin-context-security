package de.invesdwin.context.security.crypto.encryption.cipher;

import java.security.Key;

import de.invesdwin.context.security.crypto.key.IKey;

public interface ICipherKey extends IKey {

    ICipherAlgorithm getAlgorithm();

    default Key getKey(final CipherMode mode) {
        return mode.getKey(this);
    }

    Key getDecryptKey();

    Key getEncryptKey();

}
