package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.EncryptionDelegateSerde;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.AsymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.AsymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.StreamingAsymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.StreamingAsymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class AsymmetricEncryptionFactory implements IEncryptionFactory {

    private final IAsymmetricCipherAlgorithm algorithm;
    private final AsymmetricCipherKey key;

    public AsymmetricEncryptionFactory(final byte[] publicKey, final byte[] privateKey, final int keySizeBits) {
        this(IAsymmetricCipherAlgorithm.getDefault(), publicKey, privateKey, keySizeBits);
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm, final byte[] publicKey,
            final byte[] privateKey, final int keySizeBits) {
        this(new AsymmetricCipherKey(algorithm, publicKey, privateKey, keySizeBits));
    }

    public AsymmetricEncryptionFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(IAsymmetricCipherAlgorithm.getDefault(), derivedKeyProvider);
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        this(new AsymmetricCipherKey(algorithm, derivedKeyProvider));
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider, final int derivedKeySizeBits) {
        this(new AsymmetricCipherKey(algorithm, derivedKeyProvider, derivedKeySizeBits));
    }

    public AsymmetricEncryptionFactory(final AsymmetricCipherKey key) {
        this.algorithm = key.getAlgorithm();
        this.key = key;
    }

    @Override
    public IAsymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public AsymmetricCipherKey getKey() {
        return key;
    }

    @SuppressWarnings("deprecation")
    @Override
    public int init(final CipherMode mode, final ICipher cipher, final IKey key, final IByteBuffer paramBuffer) {
        cipher.init(mode, key, algorithm.getParam());
        return 0;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        try {
            return new AsymmetricCipherOutputStream(algorithm, out, cipher, key);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        try {
            return new AsymmetricCipherInputStream(algorithm, in, cipher, key);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        try {
            return new StreamingAsymmetricCipherOutputStream(algorithm, out, cipher, key);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        try {
            return new StreamingAsymmetricCipherInputStream(algorithm, in, cipher, key);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        cipher.init(CipherMode.Encrypt, key, algorithm.getParam());
        final int length = cipher.doFinal(src, dest);
        return length;
    }

    @SuppressWarnings("deprecation")
    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        cipher.init(CipherMode.Decrypt, key, algorithm.getParam());
        final int length = cipher.doFinal(src, dest);
        return length;
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde, final IKey key) {
        return new EncryptionDelegateSerde<>(serde, this, key);
    }

}
