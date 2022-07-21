package de.invesdwin.context.security.crypto.encryption.cipher.pool;

import org.apache.commons.crypto.cipher.CryptoCipher;

public interface ICryptoCipherFactory {

    CryptoCipher newCryptoCipher();

}
