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
    private final int keySizeBits;

    public HashKey(final IHashAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getDefaultKeySizeBits());
    }

    public HashKey(final IHashAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeySizeBits) {
        this(derivedKeyProvider.newDerivedKey(algorithm, ("hash-key-" + algorithm.getAlgorithm()).getBytes(),
                derivedKeySizeBits));
    }

    public HashKey(final IHashAlgorithm algorithm, final byte[] key) {
        this(algorithm, new SecretKeySpec(key, algorithm.getKeyAlgorithm()));
    }

    private HashKey(final HashKey hashKey) {
        this.algorithm = hashKey.algorithm;
        this.key = hashKey.key;
        this.keySizeBits = hashKey.keySizeBits;
    }

    public HashKey(final IHashAlgorithm algorithm, final Key key) {
        this.algorithm = algorithm;
        this.key = key;
        this.keySizeBits = key.getEncoded().length * Byte.SIZE;
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
    public int getKeySizeBits() {
        return keySizeBits;
    }

    @Override
    public int getKeyBlockSize() {
        return keySizeBits;
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
        final byte[] randomKey = ByteBuffers.allocateByteArray(keySizeBits);
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            random.nextBytes(randomKey);
            return new HashKey(algorithm, randomKey);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T unwrap(final Class<T> type) {
        if (type.isAssignableFrom(getClass())) {
            return (T) this;
        } else {
            return null;
        }
    }

}
