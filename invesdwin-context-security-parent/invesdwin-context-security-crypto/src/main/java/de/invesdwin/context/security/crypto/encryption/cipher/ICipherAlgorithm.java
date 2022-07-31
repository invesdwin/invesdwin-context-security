package de.invesdwin.context.security.crypto.encryption.cipher;

import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface ICipherAlgorithm extends ICipherFactory {

    String getKeyAlgorithm();

    String getAlgorithm();

    int getDefaultKeySize();

    IObjectPool<ICipher> getCipherPool();

}
