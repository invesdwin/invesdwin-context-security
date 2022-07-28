package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.encryption.EncryptionDelegateSerde;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.AsymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.AsymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.StreamingAsymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.StreamingAsymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class AsymmetricEncryptionFactory implements IEncryptionFactory {

    private final IAsymmetricCipherAlgorithm algorithm;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public AsymmetricEncryptionFactory(final byte[] publicKey, final byte[] privateKey) {
        this(IAsymmetricCipherAlgorithm.DEFAULT, publicKey, privateKey);
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm, final byte[] publicKey,
            final byte[] privateKey) {
        this(algorithm, algorithm.wrapPublicKey(publicKey), algorithm.wrapPrivateKey(privateKey));
    }

    public AsymmetricEncryptionFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(IAsymmetricCipherAlgorithm.DEFAULT, derivedKeyProvider);
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKeyPair(algorithm.getKeyAlgorithm(), "key-pair".getBytes(),
                RsaKeyLength.DEFAULT.getBytes()));
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm, final KeyPair keyPair) {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate());
    }

    public AsymmetricEncryptionFactory(final IAsymmetricCipherAlgorithm algorithm, final PublicKey publicKey,
            final PrivateKey privateKey) {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public void init(final ICipher cipher, final int mode, final AlgorithmParameterSpec param) {
        switch (mode) {
        case Cipher.ENCRYPT_MODE:
            cipher.init(mode, publicKey, param);
            break;
        case Cipher.DECRYPT_MODE:
            cipher.init(mode, privateKey, param);
            break;
        default:
            throw UnknownArgumentException.newInstance(int.class, mode);
        }
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out) {
        return newEncryptor(out, algorithm.newCipher());
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher) {
        try {
            return new AsymmetricCipherOutputStream(algorithm, out, cipher, publicKey);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        return newDecryptor(in, algorithm.newCipher());
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        try {
            return new AsymmetricCipherInputStream(algorithm, in, cipher, privateKey);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out) {
        return newStreamingEncryptor(out, algorithm.newCipher());
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher) {
        try {
            return new StreamingAsymmetricCipherOutputStream(algorithm, out, cipher, publicKey);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in) {
        return newStreamingDecryptor(in, algorithm.newCipher());
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher) {
        try {
            return new StreamingAsymmetricCipherInputStream(algorithm, in, cipher, privateKey);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = algorithm.getCipherPool().borrowObject();
        try {
            return encrypt(src, dest, cipher);
        } finally {
            algorithm.getCipherPool().returnObject(cipher);
        }
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        init(cipher, Cipher.ENCRYPT_MODE, algorithm.getParam());
        final int length = cipher.doFinal(src, dest);
        return length;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = algorithm.getCipherPool().borrowObject();
        try {
            return decrypt(src, dest, cipher);
        } finally {
            algorithm.getCipherPool().returnObject(cipher);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        init(cipher, Cipher.DECRYPT_MODE, algorithm.getParam());
        final int length = cipher.doFinal(src, dest);
        return length;
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde) {
        return new EncryptionDelegateSerde<>(serde, this);
    }

}
