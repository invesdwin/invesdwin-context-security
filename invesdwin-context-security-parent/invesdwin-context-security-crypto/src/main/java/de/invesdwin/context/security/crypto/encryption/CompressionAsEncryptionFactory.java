package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.integration.compression.ICompressionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
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
    public void init(final ICipher cipher, final int mode, final AlgorithmParameterSpec param) {
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
    public InputStream newDecryptor(final InputStream in) {
        return compressionFactory.newDecompressor(in);
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return newDecryptor(in);
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
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        return compressionFactory.decompress(src, dest);
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        return decrypt(src, dest);
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return compressionFactory.maybeWrap(delegate);
    }

}
