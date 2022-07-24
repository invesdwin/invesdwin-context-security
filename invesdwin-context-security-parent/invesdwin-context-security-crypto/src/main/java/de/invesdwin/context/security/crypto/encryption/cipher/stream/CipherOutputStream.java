package de.invesdwin.context.security.crypto.encryption.cipher.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.util.assertions.Assertions;

/**
 * {@link CipherOutputStream} encrypts data and writes to the under layer output. It supports any mode of operations
 * such as AES CBC/CTR/GCM mode in concept. It is not thread-safe.
 * <p>
 * This class should only be used with blocking sinks. Using this class to wrap a non-blocking sink may lead to high CPU
 * usage.
 * </p>
 * 
 * Adapted from: org.apache.commons.crypto.stream.CryptoOutputStream
 */
@NotThreadSafe
public class CipherOutputStream extends OutputStream implements WritableByteChannel {

    protected final ICipherAlgorithm algorithm;
    /** the ICipher instance */
    protected final ICipher cipher;
    /** The output. */
    protected final Output output;

    /** Crypto key for the cipher. */
    protected final Key key;

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

    /** the algorithm parameters */
    private final AlgorithmParameterSpec params;

    /** Flag to mark whether the output stream is closed. */
    private boolean closed;

    public CipherOutputStream(final ICipherAlgorithm algorithm, final OutputStream outputStream, final byte[] key,
            final byte[] iv) throws IOException {
        this(algorithm, outputStream, algorithm.newCipher(), CipherInputStream.getDefaultBufferSize(), key, iv);
    }

    public CipherOutputStream(final ICipherAlgorithm algorithm, final WritableByteChannel out, final byte[] key,
            final byte[] iv) throws IOException {
        this(algorithm, out, algorithm.newCipher(), CipherInputStream.getDefaultBufferSize(), key, iv);
    }

    protected CipherOutputStream(final ICipherAlgorithm algorithm, final OutputStream outputStream,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, new StreamOutput(outputStream, bufferSize), cipher, bufferSize, key, iv);
    }

    protected CipherOutputStream(final ICipherAlgorithm algorithm, final WritableByteChannel channel,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, new ChannelOutput(channel), cipher, bufferSize, key, iv);
    }

    protected CipherOutputStream(final ICipherAlgorithm algorithm, final Output output, final ICipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this.algorithm = algorithm;
        this.output = output;
        this.bufferSize = CipherInputStream.checkBufferSize(cipher, bufferSize);
        this.cipher = cipher;

        this.key = algorithm.wrapKey(key);
        this.params = algorithm.wrapIv(iv);

        inBuffer = java.nio.ByteBuffer.allocateDirect(this.bufferSize);
        outBuffer = java.nio.ByteBuffer.allocateDirect(this.bufferSize + cipher.getBlockSize());

        initCipher();
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
    protected void initCipher() throws IOException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
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
        CipherInputStream.freeDirectBuffer(inBuffer);
        CipherInputStream.freeDirectBuffer(outBuffer);
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