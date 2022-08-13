package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.hmac.HmacAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.pool.IHashFactory;
import de.invesdwin.util.collections.Arrays;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface IHashAlgorithm extends IHashFactory {

    IHashAlgorithm DEFAULT = HmacAlgorithm.DEFAULT;

    IHashAlgorithm[] VALUES = Arrays.concat(IHashAlgorithm.class, ChecksumAlgorithm.values(), DigestAlgorithm.values(),
            HmacAlgorithm.values(), CmacAlgorithm.values(), GmacAlgorithm.values(), KmacAlgorithm.values(),
            SkeinMacAlgorithm.values());

    int DYNAMIC_HASH_SIZE = -1;

    String getKeyAlgorithm();

    String getAlgorithm();

    int getDefaultKeySize();

    int getHashSize();

    default boolean isDynamicHashSize() {
        return getHashSize() <= DYNAMIC_HASH_SIZE;
    }

    HashAlgorithmType getType();

    IObjectPool<IHash> getHashPool();

}
