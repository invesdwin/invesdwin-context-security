package de.invesdwin.context.security.crypto.encryption.cipher.pool;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;

public interface ICipherFactory {

    ICipher newCipher();

}
