package de.invesdwin.context.security.crypto.verification.hash;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

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
        this(derivedKeyProvider.newDerivedKey(algorithm, ("hash-key-" + algorithm.getAlgorithm()).getBytes(),
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
    public int getPrimaryKeySize() {
        return keySize;
    }

    @Override
    public int getKeyBlockSize() {
        return keySize;
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        final byte[] keyBytes = key.getEncoded();
        buffer.putBytes(0, keyBytes);
        return keyBytes.length;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        final byte[] keyBytes = buffer.asByteArrayCopy();
        return new HashKey(algorithm, keyBytes);
    }

    @Override
    public IKey newRandomInstance() {
        final byte[] randomKey = ByteBuffers.allocateByteArray(keySize);
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            random.nextBytes(randomKey);
            return new HashKey(algorithm, randomKey);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
    }

}
