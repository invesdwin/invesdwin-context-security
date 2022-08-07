package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class SignatureCipherKey extends AsymmetricCipherKey {

    public SignatureCipherKey(final IAsymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        super(algorithm, derivedKeyProvider);
    }

    public SignatureCipherKey(final IAsymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeyLength) {
        super(algorithm, derivedKeyProvider, derivedKeyLength);
    }

    public SignatureCipherKey(final IAsymmetricCipherAlgorithm algorithm, final byte[] publicKey,
            final byte[] privateKey, final int keySize) {
        super(algorithm, publicKey, privateKey, keySize);
    }

    public SignatureCipherKey(final IAsymmetricCipherAlgorithm algorithm, final KeyPair keyPair, final int keySize) {
        super(algorithm, keyPair, keySize);
    }

    protected SignatureCipherKey(final SignatureCipherKey asymmetricKey) {
        super(asymmetricKey);
    }

    public SignatureCipherKey(final IAsymmetricCipherAlgorithm algorithm, final PublicKey publicKey,
            final PrivateKey privateKey, final int keySize) {
        super(algorithm, publicKey, privateKey, keySize);
    }

    @Override
    public Key getEncryptKey() {
        return super.getDecryptKey();
    }

    @Override
    public Key getDecryptKey() {
        return super.getEncryptKey();
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        int position = 0;
        final int keySize = buffer.getInt(position);
        position += Integer.BYTES;
        final int publicKeySize = buffer.getInt(position);
        position += Integer.BYTES;
        final byte[] publicKeyBytes = ByteBuffers.allocateByteArray(publicKeySize);
        buffer.getBytes(position, publicKeyBytes);
        position += publicKeyBytes.length;
        final byte[] privateKeyBytes = ByteBuffers.allocateByteArray(buffer.remaining(position));
        buffer.getBytes(position, privateKeyBytes);
        position += privateKeyBytes.length;
        return new SignatureCipherKey(getAlgorithm(), publicKeyBytes, privateKeyBytes, keySize);
    }

    @Override
    public IKey newRandomInstance() {
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(getAlgorithm().getKeyAlgorithm());
            final int lengthBits = getKeySize() * Byte.SIZE;
            generator.initialize(lengthBits, random);
            final KeyPair keyPair = generator.generateKeyPair();
            return new SignatureCipherKey(getAlgorithm(), keyPair, getKeySize());
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
    }

}
