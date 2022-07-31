package de.invesdwin.context.security.crypto.verification.hash;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;

@Immutable
public class HashKey implements IHashKey {

    private final IHashAlgorithm algorithm;
    private final Key key;
    private final int keySize;

    public HashKey(final IHashAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getKeySize());
    }

    public HashKey(final IHashAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeySize) {
        this(derivedKeyProvider.newDerivedKey(algorithm, ("hash-key-" + algorithm.getKeyAlgorithm()).getBytes(),
                derivedKeySize));
    }

    public HashKey(final IHashAlgorithm algorithm, final byte[] key) {
        this(algorithm, new SecretKeySpec(key, algorithm.getKeyAlgorithm()));
    }

    private HashKey(final HashKey hashKey) {
        this.algorithm = hashKey.algorithm;
        this.key = hashKey.key;
        this.keySize = hashKey.keySize;
    }

    public HashKey(final IHashAlgorithm algorithm, final Key key) {
        this.algorithm = algorithm;
        this.key = key;
        this.keySize = key.getEncoded().length;
    }

    @Override
    public IHashAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public Key getKey(final HashMode mode) {
        return key;
    }

    @Override
    public Key getSignKey() {
        return key;
    }

    @Override
    public Key getVerifyKey() {
        return key;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

}
