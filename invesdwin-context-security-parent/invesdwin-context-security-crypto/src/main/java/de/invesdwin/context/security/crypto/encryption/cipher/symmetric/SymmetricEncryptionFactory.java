package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.EncryptionDelegateSerde;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingSymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingSymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.SymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.SymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.ALazyDelegateInputStream;
import de.invesdwin.util.streams.ALazyDelegateOutputStream;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Derived IV is the best compromise between security and speed. It does not send the IV over the wire, instead it only
 * sends the counter (sequence number which has half the length of the IV). It expects both sides to use the same key
 * agreement protocol for the derivedIV and counted derivations of it.
 * 
 * Key derivation techniques are: Password+PBKDF2+HKDFexpands or Random+HKDFextract+HKDFexpands
 * 
 * We can derive AES-KEY, AES-IV, MAC-KEY from the initial Password or Random. scrypt and bcrypt are alternatives to
 * PBKDF2
 */
@Immutable
public class SymmetricEncryptionFactory implements IEncryptionFactory {

    private final ISymmetricCipherAlgorithm algorithm;
    private final SymmetricCipherKey key;

    public SymmetricEncryptionFactory(final byte[] derivedKey, final byte[] derivedIV) {
        this(ISymmetricCipherAlgorithm.DEFAULT, derivedKey,
                new CipherDerivedIV(ISymmetricCipherAlgorithm.DEFAULT, derivedIV));
    }

    public SymmetricEncryptionFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(ISymmetricCipherAlgorithm.DEFAULT, derivedKeyProvider);
    }

    public SymmetricEncryptionFactory(final ISymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, new SymmetricCipherKey(algorithm, derivedKeyProvider));
    }

    public SymmetricEncryptionFactory(final ISymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider, final int derivedKeyLength) {
        this(algorithm, new SymmetricCipherKey(algorithm, derivedKeyProvider, derivedKeyLength));
    }

    public SymmetricEncryptionFactory(final ISymmetricCipherAlgorithm algorithm, final byte[] key,
            final ICipherIV cipherIV) {
        this(algorithm, new SymmetricCipherKey(algorithm, key, cipherIV));
    }

    public SymmetricEncryptionFactory(final ISymmetricCipherAlgorithm algorithm, final SymmetricCipherKey key) {
        this.algorithm = algorithm;
        this.key = key;
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public IObjectPool<ICipher> getCipherPool() {
        return key.getCipherIV().getCipherPool();
    }

    @Override
    public SymmetricCipherKey getKey() {
        return key;
    }

    @Override
    public int init(final CipherMode mode, final ICipher cipher, final IKey key, final IByteBuffer paramBuffer) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        final ICipherIV cipherIV = cKey.getCipherIV();
        final MutableIvParameterSpec iv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(cipherIV.getAlgorithm().getIvSize()));
        final int length;
        switch (mode) {
        case Encrypt:
            length = cipherIV.putIV(paramBuffer, iv);
            break;
        case Decrypt:
            cipherIV.getIV(paramBuffer, iv);
            length = 0;
            break;
        default:
            throw UnknownArgumentException.newInstance(CipherMode.class, mode);
        }
        cipher.init(mode, key, cipherIV.wrapParam(iv));
        return length;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                final byte[] iv = cKey.getCipherIV().putNewIV(out);
                try {
                    return new SymmetricCipherOutputStream(algorithm, out, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final byte[] iv = cKey.getCipherIV().getNewIV(in);
                try {
                    return new SymmetricCipherInputStream(algorithm, in, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                final byte[] iv = cKey.getCipherIV().putNewIV(out);
                try {
                    return new StreamingSymmetricCipherOutputStream(algorithm, out, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final byte[] iv = cKey.getCipherIV().getNewIV(in);
                try {
                    return new StreamingSymmetricCipherInputStream(algorithm, in, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        final ICipherIV cipherIV = cKey.getCipherIV();
        final MutableIvParameterSpec iv = cipherIV.borrowDestIV();
        try {
            cipherIV.putIV(dest, iv);
            cipher.init(CipherMode.Encrypt, key, cipherIV.wrapParam(iv));
            final IByteBuffer payloadBuffer = dest.sliceFrom(cipherIV.getIvBlockSize());
            final int length = cipher.doFinal(src, payloadBuffer);
            return cipherIV.getIvBlockSize() + length;
        } finally {
            cipherIV.returnDestIV(iv);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final SymmetricCipherKey cKey = (SymmetricCipherKey) key;
        final ICipherIV cipherIV = cKey.getCipherIV();
        final MutableIvParameterSpec iv = cipherIV.borrowDestIV();
        try {
            cipherIV.getIV(src, iv);
            cipher.init(CipherMode.Decrypt, key, cipherIV.wrapParam(iv));
            final IByteBuffer payloadBuffer = src.sliceFrom(cipherIV.getIvBlockSize());
            final int length = cipher.doFinal(payloadBuffer, dest);
            return length;
        } finally {
            cipherIV.returnDestIV(iv);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde, final IKey key) {
        return new EncryptionDelegateSerde<>(serde, this, key);
    }

}
