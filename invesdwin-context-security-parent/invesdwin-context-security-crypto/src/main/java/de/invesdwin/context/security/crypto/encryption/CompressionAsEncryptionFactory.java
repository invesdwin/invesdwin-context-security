package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.integration.compression.ICompressionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class CompressionAsEncryptionFactory implements IEncryptionFactory {

    private final ICompressionFactory compressionFactory;

    public CompressionAsEncryptionFactory(final ICompressionFactory compressionFactory) {
        this.compressionFactory = compressionFactory;
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
    public int init(final CipherMode mode, final ICipher cipher, final IKey key, final IByteBuffer paramBuffer) {
        return 0;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out) {
        return compressionFactory.newCompressor(out, false);
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
        return compressionFactory.newDecompressor(in);
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return newStreamingDecryptor(in);
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return newStreamingDecryptor(in);
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out) {
        return compressionFactory.newCompressor(out, false);
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
        return compressionFactory.newDecompressor(in);
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
        return compressionFactory.compress(src, dest);
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
        return compressionFactory.decompress(src, dest);
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        return decrypt(src, dest);
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        return compressionFactory.decompress(src, dest);
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate, final IKey key) {
        return compressionFactory.maybeWrap(delegate);
    }

}
