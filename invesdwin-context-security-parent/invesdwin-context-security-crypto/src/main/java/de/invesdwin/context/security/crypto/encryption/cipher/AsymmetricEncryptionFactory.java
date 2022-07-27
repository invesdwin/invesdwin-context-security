package de.invesdwin.context.security.crypto.encryption.cipher;

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
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.rsa.RsaKeyLength;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.ALazyDelegateInputStream;
import de.invesdwin.util.streams.ALazyDelegateOutputStream;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class AsymmetricEncryptionFactory implements IEncryptionFactory {

    private final ICipherAlgorithm algorithm;
    private final PublicKey encryptionKey;
    private final PrivateKey decryptionKey;

    public AsymmetricEncryptionFactory(final byte[] publicKey, final byte[] privateKey) {
        this(ICipherAlgorithm.DEFAULT_ASYMMETRIC, publicKey, privateKey);
    }

    public AsymmetricEncryptionFactory(final ICipherAlgorithm algorithm, final byte[] publicKey,
            final byte[] privateKey) {
        this(algorithm, algorithm.wrapPublicKey(publicKey), algorithm.wrapPrivateKey(privateKey));
    }

    public AsymmetricEncryptionFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(ICipherAlgorithm.DEFAULT_ASYMMETRIC, derivedKeyProvider);
    }

    public AsymmetricEncryptionFactory(final ICipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKeyPair(algorithm.getKeyAlgorithm(), "key-pair".getBytes(),
                RsaKeyLength.DEFAULT.getBytes()));
    }

    public AsymmetricEncryptionFactory(final ICipherAlgorithm algorithm, final KeyPair keyPair) {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate());
    }

    public AsymmetricEncryptionFactory(final ICipherAlgorithm algorithm, final PublicKey encryptionKey,
            final PrivateKey decryptionKey) {
        this.algorithm = algorithm;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public void init(final ICipher cipher, final int mode, final AlgorithmParameterSpec param) {
        switch (mode) {
        case Cipher.ENCRYPT_MODE:
            cipher.init(mode, encryptionKey, param);
            break;
        case Cipher.DECRYPT_MODE:
            cipher.init(mode, decryptionKey, param);
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
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                //                final byte[] iv = cipherIV.putNewIV(out);
                //                return algorithm.newEncryptor(out, cipher, key, iv);
                return null;
            }
        };
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        return newDecryptor(in, algorithm.newCipher());
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                //                final byte[] iv = cipherIV.getNewIV(in);
                //                return algorithm.newDecryptor(in, cipher, key, iv);
                return null;
            }
        };
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
