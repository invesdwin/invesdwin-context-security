package de.invesdwin.context.security.crypto.encryption.cipher.stream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.ReadableByteChannel;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import org.agrona.BufferUtil;
import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.stream.CtrCryptoInputStream;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.utils.Utils;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.system.properties.SystemProperties;
import de.invesdwin.util.assertions.Assertions;

/**
 * CryptoInputStream reads input data and decrypts data in stream manner. It supports any mode of operations such as AES
 * CBC/CTR/GCM mode in concept. It is not thread-safe.
 * 
 * Adapted from: org.apache.commons.crypto.stream.CryptoInputStream
 */
@NotThreadSafe
public class CipherInputStream extends InputStream implements ReadableByteChannel {

    /**
     * The configuration key of the buffer size for stream.
     */
    public static final String STREAM_BUFFER_SIZE_KEY = Crypto.CONF_PREFIX + "stream.buffer.size";

    // stream related configuration keys
    /**
     * The default value of the buffer size for stream.
     */
    private static final int STREAM_BUFFER_SIZE_DEFAULT = 8192;

    private static final int MIN_BUFFER_SIZE = 512;

    protected ICipherAlgorithm algorithm;
    /** The ICipher instance. */
    protected final ICipher cipher;

    /** Crypto key for the cipher. */
    protected final Key key;

    /** The input data. */
    protected Input input;

    /**
     * Input data buffer. The data starts at inBuffer.position() and ends at to inBuffer.limit().
     */
    protected java.nio.ByteBuffer inBuffer;

    /**
     * The decrypted data buffer. The data starts at outBuffer.position() and ends at outBuffer.limit().
     */
    protected java.nio.ByteBuffer outBuffer;

    private final byte[] oneByteBuf = new byte[1];
    /** The buffer size. */
    private final int bufferSize;

    /** the algorithm parameters */
    private final AlgorithmParameterSpec params;

    /** Flag to mark whether the input stream is closed. */
    private boolean closed;

    /**
     * Flag to mark whether do final of the cipher to end the decrypting stream.
     */
    private boolean finalDone = false;

    public CipherInputStream(final ICipherAlgorithm algorithm, final InputStream inputStream, final byte[] key,
            final byte[] iv) throws IOException {
        this(algorithm, inputStream, algorithm.newCipher(), CipherInputStream.getDefaultBufferSize(), key, iv);
    }

    public CipherInputStream(final ICipherAlgorithm algorithm, final ReadableByteChannel channel, final byte[] key,
            final byte[] iv) throws IOException {
        this(algorithm, channel, algorithm.newCipher(), CipherInputStream.getDefaultBufferSize(), key, iv);
    }

    protected CipherInputStream(final ICipherAlgorithm algorithm, final InputStream inputStream, final ICipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, new StreamInput(inputStream, bufferSize), cipher, bufferSize, key, iv);
    }

    protected CipherInputStream(final ICipherAlgorithm algorithm, final ReadableByteChannel channel,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, new ChannelInput(channel), cipher, bufferSize, key, iv);
    }

    protected CipherInputStream(final ICipherAlgorithm algorithm, final Input input, final ICipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this.algorithm = algorithm;
        this.input = input;
        this.cipher = cipher;
        this.bufferSize = CipherInputStream.checkBufferSize(cipher, bufferSize);

        this.key = algorithm.wrapKey(key);
        this.params = algorithm.wrapIv(iv);

        inBuffer = java.nio.ByteBuffer.allocateDirect(this.bufferSize);
        outBuffer = java.nio.ByteBuffer
                .allocateDirect(this.bufferSize + cipher.getBlockSize() + cipher.getSignatureSize());
        outBuffer.limit(0);

        initCipher();
    }

    /**
     * Overrides the {@link java.io.InputStream#read()}. Reads the next byte of data from the input stream.
     *
     * @return the next byte of data, or {@code -1} if the end of the stream is reached.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public int read() throws IOException {
        int n;
        //CHECKSTYLE:OFF
        while ((n = read(oneByteBuf, 0, 1)) == 0) {
            /* no op */
        }
        //CHECKSTYLE:ON
        return (n == -1) ? -1 : oneByteBuf[0] & 0xff;
    }

    /**
     * Overrides the {@link java.io.InputStream#read(byte[], int, int)}. Decryption is buffer based. If there is data in
     * {@link #outBuffer}, then read it out of this buffer. If there is no data in {@link #outBuffer}, then read more
     * from the underlying stream and do the decryption.
     *
     * @param array
     *            the buffer into which the decrypted data is read.
     * @param off
     *            the buffer offset.
     * @param len
     *            the maximum number of decrypted data bytes to read.
     * @return int the total number of decrypted data bytes read into the buffer.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public int read(final byte[] array, final int off, final int len) throws IOException {
        checkStream();
        Assertions.checkNotNull(array, "array");
        if (off < 0 || len < 0 || len > array.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        final int remaining = outBuffer.remaining();
        if (remaining > 0) {
            // Satisfy the read with the existing data
            final int n = Math.min(len, remaining);
            outBuffer.get(array, off, n);
            return n;
        }
        // No data in the out buffer, try read new data and decrypt it
        // we loop for new data
        int nd = 0;
        while (nd == 0) {
            nd = decryptMore();
        }
        if (nd < 0) {
            return nd;
        }

        final int n = Math.min(len, outBuffer.remaining());
        outBuffer.get(array, off, n);
        return n;
    }

    /**
     * Overrides the {@link java.io.InputStream#skip(long)}. Skips over and discards {@code n} bytes of data from this
     * input stream.
     *
     * @param n
     *            the number of bytes to be skipped.
     * @return the actual number of bytes skipped.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public long skip(final long n) throws IOException {
        Utils.checkArgument(n >= 0, "Negative skip length.");
        checkStream();

        if (n == 0) {
            return 0;
        }

        long remaining = n;
        int nd;

        while (remaining > 0) {
            if (remaining <= outBuffer.remaining()) {
                // Skip in the remaining buffer
                final int pos = outBuffer.position() + (int) remaining;
                outBuffer.position(pos);

                remaining = 0;
                break;
            }
            remaining -= outBuffer.remaining();
            outBuffer.clear();

            // we loop for new data
            nd = 0;
            while (nd == 0) {
                nd = decryptMore();
            }
            if (nd < 0) {
                break;
            }
        }

        return n - remaining;
    }

    /**
     * Overrides the {@link InputStream#available()}. Returns an estimate of the number of bytes that can be read (or
     * skipped over) from this input stream without blocking by the next invocation of a method for this input stream.
     *
     * @return an estimate of the number of bytes that can be read (or skipped over) from this input stream without
     *         blocking or {@code 0} when it reaches the end of the input stream.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public int available() throws IOException {
        checkStream();

        return input.available() + outBuffer.remaining();
    }

    /**
     * Overrides the {@link InputStream#close()}. Closes this input stream and releases any system resources associated
     * with the stream.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        input.close();
        freeBuffers();
        cipher.close();
        super.close();
        closed = true;
    }

    /**
     * Overrides the {@link InputStream#markSupported()}.
     *
     * @return false,the {@link CtrCryptoInputStream} don't support the mark method.
     */
    @Override
    public boolean markSupported() {
        return false;
    }

    /**
     * Overrides the {@link java.nio.channels.Channel#isOpen()}.
     *
     * @return {@code true} if, and only if, this channel is open.
     */
    @Override
    public boolean isOpen() {
        return !closed;
    }

    /**
     * Overrides the ReadableByteChannel.read(ByteBuffer). Reads a sequence of bytes from this channel into the given
     * buffer.
     *
     * @param dst
     *            The buffer into which bytes are to be transferred.
     * @return The number of bytes read, possibly zero, or {@code -1} if the channel has reached end-of-stream.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public int read(final java.nio.ByteBuffer dst) throws IOException {
        checkStream();
        int remaining = outBuffer.remaining();
        if (remaining <= 0) {
            // Decrypt more data
            // we loop for new data
            int nd = 0;
            while (nd == 0) {
                nd = decryptMore();
            }

            if (nd < 0) {
                return -1;
            }
        }

        // Copy decrypted data from outBuffer to dst
        remaining = outBuffer.remaining();
        final int toRead = dst.remaining();
        if (toRead <= remaining) {
            final int limit = outBuffer.limit();
            outBuffer.limit(outBuffer.position() + toRead);
            dst.put(outBuffer);
            outBuffer.limit(limit);
            return toRead;
        }
        dst.put(outBuffer);
        return remaining;
    }

    /**
     * Gets the buffer size.
     *
     * @return the bufferSize.
     */
    protected int getBufferSize() {
        return bufferSize;
    }

    /**
     * Gets the key.
     *
     * @return the key.
     */
    protected Key getKey() {
        return key;
    }

    /**
     * Gets the internal ICipher.
     *
     * @return the cipher instance.
     */
    protected ICipher getCipher() {
        return cipher;
    }

    /**
     * Gets the specification of cryptographic parameters.
     *
     * @return the params.
     */
    protected AlgorithmParameterSpec getParams() {
        return params;
    }

    /**
     * Gets the input.
     *
     * @return the input.
     */
    protected Input getInput() {
        return input;
    }

    /**
     * Initializes the cipher.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void initCipher() throws IOException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } catch (final Exception e) {
            throw new IOException(e);
        }
    }

    /**
     * Decrypts more data by reading the under layer stream. The decrypted data will be put in the output buffer. If the
     * end of the under stream reached, we will do final of the cipher to finish all the decrypting of data.
     *
     * @return The number of decrypted data. return -1 (if end of the decrypted stream) return 0 (no data now, but could
     *         have more later)
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected int decryptMore() throws IOException {
        if (finalDone) {
            return -1;
        }

        final int n = input.read(inBuffer);
        if (n < 0) {
            // The stream is end, finalize the cipher stream
            decryptFinal();

            // Satisfy the read with the remaining
            final int remaining = outBuffer.remaining();
            if (remaining > 0) {
                return remaining;
            }

            // End of the stream
            return -1;
        } else if (n == 0) {
            // No data is read, but the stream is not end yet
            return 0;
        } else {
            decrypt();
            return outBuffer.remaining();
        }
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output. Upon return, inBuffer is cleared; the
     * decrypted data starts at outBuffer.position() and ends at outBuffer.limit().
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void decrypt() throws IOException {
        // Prepare the input buffer and clear the out buffer
        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.update(inBuffer, outBuffer);
        } catch (final Exception e) {
            throw new IOException(e);
        }

        // Clear the input buffer and prepare out buffer
        inBuffer.clear();
        outBuffer.flip();
    }

    /**
     * Does final of the cipher to end the decrypting stream.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void decryptFinal() throws IOException {
        // Prepare the input buffer and clear the out buffer
        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.doFinal(inBuffer, outBuffer);
            finalDone = true;
        } catch (final Exception e) {
            throw new IOException(e);
        }

        // Clear the input buffer and prepare out buffer
        inBuffer.clear();
        outBuffer.flip();
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
     * Forcibly free the direct buffer.
     *
     * @param buffer
     *            the bytebuffer to be freed.
     */
    public static void freeDirectBuffer(final java.nio.ByteBuffer buffer) {
        BufferUtil.free(buffer);
    }

    /**
     * Reads crypto buffer size.
     *
     * @param props
     *            The {@code Properties} class represents a set of properties.
     * @return the buffer size.
     */
    public static int getDefaultBufferSize() {
        final String bufferSizeStr = SystemProperties.SYSTEM_PROPERTIES
                .getProperty(CipherInputStream.STREAM_BUFFER_SIZE_KEY);
        if (bufferSizeStr == null || bufferSizeStr.isEmpty()) {
            return CipherInputStream.STREAM_BUFFER_SIZE_DEFAULT;
        }
        return Integer.parseInt(bufferSizeStr);
    }

    /**
     * Checks and floors buffer size.
     *
     * @param cipher
     *            the {@link ICipher} instance.
     * @param bufferSize
     *            the buffer size.
     * @return the remaining buffer size.
     */
    public static int checkBufferSize(final ICipher cipher, final int bufferSize) {
        Utils.checkArgument(bufferSize >= CipherInputStream.MIN_BUFFER_SIZE,
                "Minimum value of buffer size is " + CipherInputStream.MIN_BUFFER_SIZE + ".");
        return bufferSize - bufferSize % cipher.getBlockSize();
    }
}
