package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import de.invesdwin.util.streams.pool.buffered.PooledFastBufferedOutputStream;

@Immutable
public final class DisabledEncryptionFactory implements IEncryptionFactory {

    public static final DisabledEncryptionFactory INSTANCE = new DisabledEncryptionFactory();

    private DisabledEncryptionFactory() {
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public IKey getKey() {
        return null;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out) {
        return out;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher) {
        return newEncryptor(out);
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        return newEncryptor(out);
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        return in;
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return newDecryptor(in);
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return newDecryptor(in);
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out) {
        //buffering is better for write throughput to file
        return PooledFastBufferedOutputStream.newInstance(out);
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher) {
        return newStreamingEncryptor(out);
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        return newStreamingEncryptor(out);
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in) {
        return in;
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher) {
        return newStreamingDecryptor(in);
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return newStreamingDecryptor(in);
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        return encrypt(src, dest);
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        return encrypt(src, dest);
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        return decrypt(src, dest);
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        return decrypt(src, dest);
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde, final IKey key) {
        return serde;
    }

}
