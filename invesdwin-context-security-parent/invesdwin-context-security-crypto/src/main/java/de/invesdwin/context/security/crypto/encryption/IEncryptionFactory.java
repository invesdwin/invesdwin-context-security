package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IEncryptionFactory {

    ICipherAlgorithm getAlgorithm();

    IKey getKey();

    default IObjectPool<ICipher> getCipherPool() {
        return getAlgorithm().getCipherPool();
    }

    /**
     * The key might contain a CipherIV which needs data put/read to/from the paramBuffer.
     */
    int init(CipherMode mode, ICipher cipher, IKey key, IByteBuffer paramBuffer);

    /**
     * Can only be used to encrypt one payload.
     */
    default OutputStream newEncryptor(final OutputStream out) {
        return newEncryptor(out, getAlgorithm().newCipher());
    }

    default OutputStream newEncryptor(final OutputStream out, final ICipher cipher) {
        return newEncryptor(out, cipher, getKey());
    }

    OutputStream newEncryptor(OutputStream out, ICipher cipher, IKey key);

    default InputStream newDecryptor(final InputStream in) {
        return newDecryptor(in, getAlgorithm().newCipher());
    }

    default InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return newDecryptor(in, cipher, getKey());
    }

    InputStream newDecryptor(InputStream in, ICipher cipher, IKey key);

    /**
     * Can be used to encrypt multiple messages.
     */
    default OutputStream newStreamingEncryptor(final OutputStream out) {
        return newStreamingEncryptor(out, getAlgorithm().newCipher());
    }

    default OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher) {
        return newStreamingEncryptor(out, cipher, getKey());
    }

    OutputStream newStreamingEncryptor(OutputStream out, ICipher cipher, IKey key);

    default InputStream newStreamingDecryptor(final InputStream in) {
        return newStreamingDecryptor(in, getAlgorithm().newCipher());
    }

    default InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher) {
        return newStreamingDecryptor(in, cipher, getKey());
    }

    InputStream newStreamingDecryptor(InputStream in, ICipher cipher, IKey key);

    default int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = getCipherPool().borrowObject();
        try {
            return encrypt(src, dest, cipher);
        } finally {
            getCipherPool().returnObject(cipher);
        }
    }

    default int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        return encrypt(src, dest, cipher, getKey());
    }

    int encrypt(IByteBuffer src, IByteBuffer dest, ICipher cipher, IKey key);

    default int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = getCipherPool().borrowObject();
        try {
            return decrypt(src, dest, cipher);
        } finally {
            getCipherPool().returnObject(cipher);
        }
    }

    default int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        return decrypt(src, dest, cipher, getKey());
    }

    int decrypt(IByteBuffer src, IByteBuffer dest, ICipher cipher, IKey key);

    default <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return maybeWrap(delegate, getKey());
    }

    <T> ISerde<T> maybeWrap(ISerde<T> delegate, IKey key);

}
