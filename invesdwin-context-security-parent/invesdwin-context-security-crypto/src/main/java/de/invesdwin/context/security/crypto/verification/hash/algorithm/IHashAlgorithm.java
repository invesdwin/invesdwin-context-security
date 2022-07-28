package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.IHashFactory;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface IHashAlgorithm extends IHashFactory {

    IHashAlgorithm DEFAULT = HmacAlgorithm.DEFAULT;

    int getHashSize();

    HashAlgorithmType getType();

    Key wrapKey(byte[] key);

    IObjectPool<IHash> getHashPool();

}
