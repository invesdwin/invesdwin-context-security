package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherKey;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class AsymmetricCipherKey implements ICipherKey {

    private final IAsymmetricCipherAlgorithm algorithm;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySize;

    public AsymmetricCipherKey(final IAsymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getDefaultKeySize());
    }

    public AsymmetricCipherKey(final IAsymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeyLength) {
        this(derivedKeyProvider.newDerivedKey(algorithm,
                ("cipher-asymmetric-key-" + algorithm.getAlgorithm()).getBytes(), derivedKeyLength));
    }

    public AsymmetricCipherKey(final IAsymmetricCipherAlgorithm algorithm, final byte[] publicKey,
            final byte[] privateKey) {
        this(algorithm, wrapPublicKey(algorithm.getKeyAlgorithm(), publicKey),
                wrapPrivateKey(algorithm.getKeyAlgorithm(), privateKey));
    }

    public AsymmetricCipherKey(final IAsymmetricCipherAlgorithm algorithm, final KeyPair keyPair) {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate());
    }

    private AsymmetricCipherKey(final AsymmetricCipherKey asymmetricKey) {
        this.algorithm = asymmetricKey.algorithm;
        this.publicKey = asymmetricKey.publicKey;
        this.privateKey = asymmetricKey.privateKey;
        this.keySize = asymmetricKey.keySize;
    }

    public AsymmetricCipherKey(final IAsymmetricCipherAlgorithm algorithm, final PublicKey publicKey,
            final PrivateKey privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.keySize = privateKey.getEncoded().length;
    }

    @Override
    public IAsymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public Key getEncryptKey() {
        return publicKey;
    }

    @Override
    public Key getDecryptKey() {
        return privateKey;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        /*
         * HybridEncryptionFactory needs to send the private key only, though since the public key can easily be derived
         * from the private key, it does not matter if we send both. They are sent encrypted anyway and are only used as
         * session keys anyhow. Only sending the private key would not allow to restore the state on the other side for
         * bidirectional communication (if desired). Though ideally the inverse direction should use a different session
         * key anyhow (which HybridEncryptionFactory makes sure of).
         */
        final byte[] privateKeyBytes = privateKey.getEncoded();
        final byte[] publicKeyBytes = publicKey.getEncoded();
        int position = 0;
        buffer.putInt(position, privateKeyBytes.length);
        position += Integer.BYTES;
        buffer.putBytes(position, privateKeyBytes);
        position += privateKeyBytes.length;
        buffer.putBytes(position, publicKeyBytes);
        position += publicKeyBytes.length;
        return position;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        int position = 0;
        final int privateKeySize = buffer.getInt(position);
        position += Integer.BYTES;
        final byte[] privateKeyBytes = ByteBuffers.allocateByteArray(privateKeySize);
        buffer.getBytes(position, privateKeyBytes);
        position += privateKeyBytes.length;
        final byte[] publicKeyBytes = ByteBuffers.allocateByteArray(buffer.remaining(position));
        buffer.getBytes(position, publicKeyBytes);
        position += publicKeyBytes.length;
        return new AsymmetricCipherKey(algorithm, privateKeyBytes, publicKeyBytes);
    }

    public static PrivateKey wrapPrivateKey(final String keyAlgorithm, final byte[] privateKey) {
        try {
            return KeyFactory.getInstance(keyAlgorithm).generatePrivate(new PKCS8EncodedKeySpec(privateKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey wrapPublicKey(final String keyAlgorithm, final byte[] publicKey) {
        try {
            return KeyFactory.getInstance(keyAlgorithm).generatePublic(new X509EncodedKeySpec(publicKey));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public IKey newRandomInstance() {
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.getKeyAlgorithm());
            final int lengthBits = keySize * Byte.SIZE;
            generator.initialize(lengthBits, random);
            final KeyPair keyPair = generator.generateKeyPair();
            return new AsymmetricCipherKey(algorithm, keyPair);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
    }

}
