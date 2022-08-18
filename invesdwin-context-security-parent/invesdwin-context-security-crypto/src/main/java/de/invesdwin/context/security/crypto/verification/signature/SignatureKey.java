package de.invesdwin.context.security.crypto.verification.signature;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricCipherKey;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerators;
import de.invesdwin.context.security.crypto.verification.signature.algorithm.ISignatureAlgorithm;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class SignatureKey implements ISignatureKey {

    private final ISignatureAlgorithm algorithm;
    private final PublicKey verifyKey;
    private final PrivateKey signKey;
    private final int keySizeBits;
    private final int signKeyBlockSize;
    private final int verifyKeyBlockSize;

    public SignatureKey(final ISignatureAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getDefaultKeySizeBits());
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeySizeBits) {
        this(derivedKeyProvider.newDerivedKey(algorithm, ("signature-key-" + algorithm.getAlgorithm()).getBytes(),
                derivedKeySizeBits));
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final byte[] verifyKey, final byte[] signKey,
            final int keySizeBits) {
        this(algorithm, wrapVerifyKey(algorithm.getKeyAlgorithm(), verifyKey),
                wrapSignKey(algorithm.getKeyAlgorithm(), signKey), keySizeBits);
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final KeyPair keyPair, final int keySizeBits) {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate(), keySizeBits);
    }

    private SignatureKey(final SignatureKey asymmetricKey) {
        this.algorithm = asymmetricKey.algorithm;
        this.verifyKey = asymmetricKey.verifyKey;
        this.signKey = asymmetricKey.signKey;
        this.keySizeBits = asymmetricKey.keySizeBits;
        this.signKeyBlockSize = asymmetricKey.signKeyBlockSize;
        this.verifyKeyBlockSize = asymmetricKey.verifyKeyBlockSize;
    }

    public SignatureKey(final ISignatureAlgorithm algorithm, final PublicKey verifyKey, final PrivateKey signKey,
            final int keySizeBits) {
        this.algorithm = algorithm;
        this.verifyKey = verifyKey;
        this.signKey = signKey;
        this.keySizeBits = keySizeBits;
        this.signKeyBlockSize = unwrapKey(signKey).length;
        this.verifyKeyBlockSize = unwrapKey(verifyKey).length;
    }

    @Override
    public ISignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public PublicKey getVerifyKey() {
        return verifyKey;
    }

    @Override
    public PrivateKey getSignKey() {
        return signKey;
    }

    @Override
    public int getKeySizeBits() {
        return keySizeBits;
    }

    @Override
    public int getKeyBlockSize() {
        return signKeyBlockSize + Integer.BYTES + verifyKeyBlockSize;
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
        final byte[] verifyKeyBytes = unwrapKey(verifyKey);
        final byte[] signKeyBytes = unwrapKey(signKey);
        int position = 0;
        buffer.putInt(position, keySizeBits);
        position += Integer.BYTES;
        buffer.putInt(position, verifyKeyBytes.length);
        position += Integer.BYTES;
        buffer.putBytes(position, verifyKeyBytes);
        position += verifyKeyBytes.length;
        buffer.putBytes(position, signKeyBytes);
        position += signKeyBytes.length;
        return position;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        int position = 0;
        final int keySizeBits = buffer.getInt(position);
        position += Integer.BYTES;
        final int verifyKeySize = buffer.getInt(position);
        position += Integer.BYTES;
        final byte[] verifyKeyBytes = ByteBuffers.allocateByteArray(verifyKeySize);
        buffer.getBytes(position, verifyKeyBytes);
        position += verifyKeyBytes.length;
        final byte[] signKeyBytes = ByteBuffers.allocateByteArray(buffer.remaining(position));
        buffer.getBytes(position, signKeyBytes);
        position += signKeyBytes.length;
        return new SignatureKey(algorithm, verifyKeyBytes, signKeyBytes, keySizeBits);
    }

    public static byte[] unwrapKey(final Key key) {
        return AsymmetricCipherKey.unwrapKey(key);
    }

    public static PrivateKey wrapSignKey(final String keyAlgorithm, final byte[] signKey) {
        return AsymmetricCipherKey.wrapPrivateKey(keyAlgorithm, signKey);
    }

    public static PublicKey wrapVerifyKey(final String keyAlgorithm, final byte[] verifyKey) {
        return AsymmetricCipherKey.wrapPublicKey(keyAlgorithm, verifyKey);
    }

    @Override
    public IKey newRandomInstance() {
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.getKeyAlgorithm());
            final int lengthBits = keySizeBits;
            generator.initialize(lengthBits, random);
            final KeyPair keyPair = generator.generateKeyPair();
            return new SignatureKey(algorithm, keyPair, keySizeBits);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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
