package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class SymmetricCipherKey implements ICipherKey {

    private final ISymmetricCipherAlgorithm algorithm;
    private final Key key;
    private final int keySizeBytes;
    private final ICipherIV cipherIV;

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getDefaultKeySizeBits());
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeySizeBits) {
        this(derivedKeyProvider.newDerivedKey(algorithm,
                ("cipher-symmetric-key-" + algorithm.getAlgorithm()).getBytes(), derivedKeySizeBits));
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final byte[] derivedKey,
            final byte[] derivedIV) {
        this(algorithm, derivedKey, new CipherDerivedIV(algorithm, derivedIV));
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final byte[] key, final ICipherIV cipherIV) {
        this(algorithm, wrapKey(algorithm.getKeyAlgorithm(), key), cipherIV);
    }

    private SymmetricCipherKey(final SymmetricCipherKey symmetricKey) {
        this.algorithm = symmetricKey.algorithm;
        this.key = symmetricKey.key;
        this.keySizeBytes = symmetricKey.keySizeBytes;
        this.cipherIV = symmetricKey.cipherIV;
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final Key key, final ICipherIV cipherIV) {
        this.algorithm = algorithm;
        this.key = key;
        this.keySizeBytes = key.getEncoded().length;
        this.cipherIV = cipherIV;
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public Key getKey(final CipherMode mode) {
        return key;
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    @Override
    public Key getEncryptKey() {
        return key;
    }

    @Override
    public Key getDecryptKey() {
        return key;
    }

    @Override
    public int getKeySizeBits() {
        return keySizeBytes * Byte.SIZE;
    }

    @Override
    public int getKeyBlockSize() {
        return keySizeBytes + Integer.BYTES + cipherIV.getIvBlockSize();
    }

    public static Key wrapKey(final String keyAlgorithm, final byte[] key) {
        return new SecretKeySpec(key, keyAlgorithm);
    }

    //CHECKSTYLE:OFF
    public SymmetricCipherKey withCipherIV(final ICipherIV cipherIV) {
        //CHECKSTYLE:ON
        return new SymmetricCipherKey(algorithm, key, cipherIV);
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        final byte[] keyBytes = key.getEncoded();
        int position = 0;
        buffer.putInt(position, keyBytes.length);
        position += Integer.BYTES;
        buffer.putBytes(position, keyBytes);
        position += keyBytes.length;
        final int cipherIvSize = cipherIV.toBuffer(buffer.sliceFrom(position));
        position += cipherIvSize;
        return position;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        int position = 0;
        final int keySize = buffer.getInt(position);
        position += Integer.BYTES;
        final byte[] keyBytes = ByteBuffers.allocateByteArray(keySize);
        buffer.getBytes(position, keyBytes);
        position += keyBytes.length;
        final ICipherIV cipherIVFromBuffer = cipherIV.fromBuffer(buffer.sliceFrom(position));
        return new SymmetricCipherKey(algorithm, keyBytes, cipherIVFromBuffer);
    }

    @Override
    public IKey newRandomInstance() {
        final byte[] randomKey = ByteBuffers.allocateByteArray(keySizeBytes);
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            random.nextBytes(randomKey);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        final ICipherIV randomCipherIV = cipherIV.newRandomInstance();
        return new SymmetricCipherKey(algorithm, randomKey, randomCipherIV);
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
