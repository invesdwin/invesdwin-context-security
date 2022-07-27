package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.IHashFactory;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface IHashAlgorithm extends IHashFactory {

    IHashAlgorithm DEFAULT = HmacAlgorithm.DEFAULT;

    int getHashSize();

    /**
     * Returns true if this is not just a verification based on a message digest but an authentication based on a mac as
     * well.
     * 
     * Normally only authenticated hashes require a key on initialization. For non-authenticated hashes the key will
     * then be used as a pepper (a static salt).
     */
    boolean isAuthentication();

    Key wrapKey(byte[] key);

    IObjectPool<IHash> getHashPool();

}
