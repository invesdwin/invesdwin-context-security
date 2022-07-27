package de.invesdwin.context.security.crypto.encryption.cipher;

import de.invesdwin.context.security.crypto.encryption.cipher.pool.CipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;

public interface ICipherAlgorithm extends ICipherFactory {

    String getKeyAlgorithm();

    /**
     * A symmetric cipher requires a key, an asymmetric cipher requires a public/private key pair.
     */
    boolean isSymmetric();

    /**
     * Requires a public/private key pair.
     */
    boolean isAsymmetric();

    CipherObjectPool getCipherPool();

}
