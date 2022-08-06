package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.crypto.stream.output.Output;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.CipherStreams;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.assertions.Assertions;

@NotThreadSafe
public class AsymmetricCipherOutputStream extends OutputStream implements WritableByteChannel {

    protected final IAsymmetricCipherAlgorithm algorithm;
    /** the ICipher instance */
    protected final ICipher cipher;
    /** The output. */
    protected final Output output;

    /** Crypto key for the cipher. */
    protected final IKey key;
    /** the algorithm parameters */
    protected final AlgorithmParameterSpec params;

    /**
     * Input data buffer. The data starts at inBuffer.position() and ends at inBuffer.limit().
     */
    protected java.nio.ByteBuffer inBuffer;

    /**
     * Encrypted data buffer. The data starts at outBuffer.position() and ends at outBuffer.limit().
     */
    protected java.nio.ByteBuffer outBuffer;

    private final byte[] oneByteBuf = new byte[1];

    /** The buffer size. */
    private final int bufferSize;

    /** Flag to mark whether the output stream is closed. */
    private boolean closed;

    public AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final OutputStream outputStream,
            final IKey key) throws IOException {
        this(algorithm, outputStream, algorithm.newCipher(), CipherStreams.getDefaultBufferSize(), key);
    }

    public AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final OutputStream outputStream,
            final ICipher cipher, final IKey key) throws IOException {
        this(algorithm, outputStream, cipher, CipherStreams.getDefaultBufferSize(), key);
    }

    public AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final WritableByteChannel out,
            final ICipher cipher, final IKey key) throws IOException {
        this(algorithm, out, cipher, CipherStreams.getDefaultBufferSize(), key);
    }

    public AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final WritableByteChannel out,
            final IKey key) throws IOException {
        this(algorithm, out, algorithm.newCipher(), CipherStreams.getDefaultBufferSize(), key);
    }

    protected AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final OutputStream outputStream,
            final ICipher cipher, final int bufferSize, final IKey key) throws IOException {
        this(algorithm, CipherStreams.wrapOutput(outputStream, bufferSize), cipher, bufferSize, key);
    }

    protected AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final int bufferSize, final IKey key)
            throws IOException {
        this(algorithm, CipherStreams.wrapOutput(channel), cipher, bufferSize, key);
    }

    protected AsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final Output output,
            final ICipher cipher, final int bufferSize, final IKey key) throws IOException {
        this.algorithm = algorithm;
        this.output = output;
        this.cipher = cipher;

        this.key = key;
        this.params = algorithm.getParam();

        initCipher();
        this.bufferSize = CipherStreams.checkBufferSize(cipher, bufferSize);
        this.inBuffer = java.nio.ByteBuffer.allocateDirect(this.bufferSize);
        this.outBuffer = java.nio.ByteBuffer
                .allocateDirect(this.bufferSize + cipher.getBlockSize() + cipher.getHashSize());
    }

    /**
     * Overrides the {@link java.io.OutputStream#write(byte[])}. Writes the specified byte to this output stream.
     *
     * @param b
     *            the data.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public void write(final int b) throws IOException {
        oneByteBuf[0] = (byte) (b & 0xff);
        write(oneByteBuf, 0, oneByteBuf.length);
    }

    /**
     * Overrides the {@link java.io.OutputStream#write(byte[], int, int)}. Encryption is buffer based. If there is
     * enough room in {@link #inBuffer}, then write to this buffer. If {@link #inBuffer} is full, then do encryption and
     * write data to the underlying stream.
     *
     * @param array
     *            the data.
     * @param off
     *            the start offset in the data.
     * @param len
     *            the number of bytes to write.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public void write(final byte[] array, final int pOff, final int pLen) throws IOException {
        int off = pOff;
        int len = pLen;
        checkStream();
        Assertions.checkNotNull(array, "array");
        if (off < 0 || len < 0 || off > array.length || len > array.length - off) {
            throw new IndexOutOfBoundsException();
        }

        while (len > 0) {
            final int remaining = inBuffer.remaining();
            if (len < remaining) {
                inBuffer.put(array, off, len);
                len = 0;
            } else {
                inBuffer.put(array, off, remaining);
                off += remaining;
                len -= remaining;
                encrypt();
            }
        }
    }

    /**
     * Overrides the {@link OutputStream#flush()}. To flush, we need to encrypt the data in the buffer and write to the
     * underlying stream, then do the flush.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public void flush() throws IOException {
        checkStream();
        encrypt();
        output.flush();
        super.flush();
    }

    /**
     * Overrides the {@link OutputStream#close()}. Closes this output stream and releases any system resources
     * associated with this stream.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        try {
            encryptFinal();
            output.close();
            freeBuffers();
            cipher.close();
            super.close();
        } finally {
            closed = true;
        }
    }

    /**
     * Overrides the {@link java.nio.channels.Channel#isOpen()}. Tells whether or not this channel is open.
     *
     * @return {@code true} if, and only if, this channel is open
     */
    @Override
    public boolean isOpen() {
        return !closed;
    }

    /**
     * Overrides the WritableByteChannel.write(ByteBuffer). Writes a sequence of bytes to this channel from the given
     * buffer.
     *
     * @param src
     *            The buffer from which bytes are to be retrieved.
     * @return The number of bytes written, possibly zero.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public int write(final java.nio.ByteBuffer src) throws IOException {
        checkStream();
        final int len = src.remaining();
        int remaining = len;
        while (remaining > 0) {
            final int space = inBuffer.remaining();
            if (remaining < space) {
                inBuffer.put(src);
                remaining = 0;
            } else {
                // to void copy twice, we set the limit to copy directly
                final int oldLimit = src.limit();
                final int newLimit = src.position() + space;
                src.limit(newLimit);

                inBuffer.put(src);

                // restore the old limit
                src.limit(oldLimit);

                remaining -= space;
                encrypt();
            }
        }

        return len;
    }

    /**
     * Initializes the cipher.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @SuppressWarnings("deprecation")
    protected void initCipher() throws IOException {
        try {
            cipher.init(CipherMode.Encrypt, key, params);
        } catch (final Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Does the encryption, input is {@link #inBuffer} and output is {@link #outBuffer}.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void encrypt() throws IOException {

        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.update(inBuffer, outBuffer);
        } catch (final Exception e) {
            throw new IOException(e);
        }

        inBuffer.clear();
        outBuffer.flip();

        // write to output
        while (outBuffer.hasRemaining()) {
            output.write(outBuffer);
        }
    }

    /**
     * Does final encryption of the last data.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void encryptFinal() throws IOException {
        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.doFinal(inBuffer, outBuffer);
        } catch (final Exception e) {
            throw new IOException(e);
        }

        inBuffer.clear();
        outBuffer.flip();

        // write to output
        while (outBuffer.hasRemaining()) {
            output.write(outBuffer);
        }
    }

    /**
     * Checks whether the stream is closed.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void checkStream() throws IOException {
        if (closed) {
            throw new IOException("Stream closed");
        }
    }

    /** Forcibly free the direct buffers. */
    protected void freeBuffers() {
        CipherStreams.freeDirectBuffer(inBuffer);
        CipherStreams.freeDirectBuffer(outBuffer);
    }

    /**
     * Gets the outBuffer.
     *
     * @return the outBuffer.
     */
    protected java.nio.ByteBuffer getOutBuffer() {
        return outBuffer;
    }

    /**
     * Gets the internal Cipher.
     *
     * @return the cipher instance.
     */
    protected ICipher getCipher() {
        return cipher;
    }

    /**
     * Gets the buffer size.
     *
     * @return the buffer size.
     */
    protected int getBufferSize() {
        return bufferSize;
    }

    /**
     * Gets the inBuffer.
     *
     * @return the inBuffer.
     */
    protected java.nio.ByteBuffer getInBuffer() {
        return inBuffer;
    }
}
