package de.invesdwin.context.security.crypto.verification.signature;

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

import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.context.security.crypto.verification.signature.algorithm.ISignatureAlgorithm;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class SignatureKey implements ISignatureKey {

    private final ISignatureAlgorithm algorithm;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private final int keySizeBits;
    private final int privateKeyBlockSize;
    private final int publicKeyBlockSize;

    public SignatureKey(final ISignatureAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getDefaultKeySizeBits());
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeySizeBits) {
        this(derivedKeyProvider.newDerivedKey(algorithm, ("signature-key-" + algorithm.getAlgorithm()).getBytes(),
                derivedKeySizeBits));
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final byte[] publicKey, final byte[] privateKey,
            final int keySizeBits) {
        this(algorithm, wrapPublicKey(algorithm.getKeyAlgorithm(), publicKey),
                wrapPrivateKey(algorithm.getKeyAlgorithm(), privateKey), keySizeBits);
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final KeyPair keyPair, final int keySizeBits) {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate(), keySizeBits);
    }

    private SignatureKey(final SignatureKey asymmetricKey) {
        this.algorithm = asymmetricKey.algorithm;
        this.publicKey = asymmetricKey.publicKey;
        this.privateKey = asymmetricKey.privateKey;
        this.keySizeBits = asymmetricKey.keySizeBits;
        this.privateKeyBlockSize = asymmetricKey.privateKeyBlockSize;
        this.publicKeyBlockSize = asymmetricKey.publicKeyBlockSize;
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final PublicKey publicKey, final PrivateKey privateKey,
            final int keySizeBits) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.keySizeBits = keySizeBits;
        this.privateKeyBlockSize = privateKey.getEncoded().length;
        this.publicKeyBlockSize = publicKey.getEncoded().length;
    }

    @Override
    public ISignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public PublicKey getVerifyKey() {
        return publicKey;
    }

    @Override
    public PrivateKey getSignKey() {
        return privateKey;
    }

    @Override
    public int getKeySizeBits() {
        return keySizeBits;
    }

    @Override
    public int getKeyBlockSize() {
        return privateKeyBlockSize + Integer.BYTES + publicKeyBlockSize;
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
        final byte[] publicKeyBytes = publicKey.getEncoded();
        final byte[] privateKeyBytes = privateKey.getEncoded();
        int position = 0;
        buffer.putInt(position, keySizeBits);
        position += Integer.BYTES;
        buffer.putInt(position, publicKeyBytes.length);
        position += Integer.BYTES;
        buffer.putBytes(position, publicKeyBytes);
        position += publicKeyBytes.length;
        buffer.putBytes(position, privateKeyBytes);
        position += privateKeyBytes.length;
        return position;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        int position = 0;
        final int keySizeBits = buffer.getInt(position);
        position += Integer.BYTES;
        final int publicKeySize = buffer.getInt(position);
        position += Integer.BYTES;
        final byte[] publicKeyBytes = ByteBuffers.allocateByteArray(publicKeySize);
        buffer.getBytes(position, publicKeyBytes);
        position += publicKeyBytes.length;
        final byte[] privateKeyBytes = ByteBuffers.allocateByteArray(buffer.remaining(position));
        buffer.getBytes(position, privateKeyBytes);
        position += privateKeyBytes.length;
        return new SignatureKey(algorithm, publicKeyBytes, privateKeyBytes, keySizeBits);
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
            final int lengthBits = keySizeBits;
            generator.initialize(lengthBits, random);
            final KeyPair keyPair = generator.generateKeyPair();
            return new SignatureKey(algorithm, keyPair, keySizeBits);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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
