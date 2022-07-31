package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherKey;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;

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
                ("cipher-asymmetric-key-" + algorithm.getKeyAlgorithm()).getBytes(), derivedKeyLength));
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

}
