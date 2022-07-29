package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import java.security.Key;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.pool.IHashFactory;
import de.invesdwin.util.collections.Arrays;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface IHashAlgorithm extends IHashFactory {

    IHashAlgorithm DEFAULT = HmacAlgorithm.DEFAULT;

    IHashAlgorithm[] VALUES = Arrays.concat(IHashAlgorithm.class, ChecksumAlgorithm.values(), DigestAlgorithm.values(),
            HmacAlgorithm.values(), CmacAlgorithm.values(), GmacAlgorithm.values());

    int getKeySize();

    int getHashSize();

    HashAlgorithmType getType();

    Key wrapKey(byte[] key);

    IObjectPool<IHash> getHashPool();

}
