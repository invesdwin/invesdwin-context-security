package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.ReadableByteChannel;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.CipherStreams;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input.ICipherInput;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;

@NotThreadSafe
public class StreamingAsymmetricCipherInputStream extends AsymmetricCipherInputStream {
    /**
     * Underlying stream offset
     */
    private long streamOffset = 0;

    /**
     * Flag to mark whether the cipher has been reset
     */
    private boolean cipherReset = false;

    public StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final InputStream inputStream, final IKey key) throws IOException {
        this(algorithm, inputStream, key, 0);
    }

    public StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final ReadableByteChannel channel, final IKey key) throws IOException {
        this(algorithm, channel, key, 0);
    }

    public StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final ReadableByteChannel channel, final ICipher cipher, final IKey key) throws IOException {
        this(algorithm, channel, cipher, CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, 0);
    }

    public StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final InputStream inputStream, final ICipher cipher, final IKey key) throws IOException {
        this(algorithm, inputStream, cipher, CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, 0);
    }

    protected StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final InputStream inputStream, final ICipher cipher, final int bufferSize, final IKey key)
            throws IOException {
        this(algorithm, inputStream, cipher, bufferSize, key, 0);
    }

    protected StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final ReadableByteChannel channel, final ICipher cipher, final int bufferSize, final IKey key)
            throws IOException {
        this(algorithm, channel, cipher, bufferSize, key, 0);
    }

    protected StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm, final ICipherInput input,
            final ICipher cipher, final int bufferSize, final IKey key) throws IOException {
        this(algorithm, input, cipher, bufferSize, key, 0);
    }

    public StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final InputStream inputStream, final IKey key, final long streamOffset) throws IOException {
        this(algorithm, inputStream, algorithm.newCipher(), CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key,
                streamOffset);
    }

    public StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final ReadableByteChannel in, final IKey key, final long streamOffset) throws IOException {
        this(algorithm, in, algorithm.newCipher(), CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, streamOffset);
    }

    protected StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final InputStream inputStream, final ICipher cipher, final int bufferSize, final IKey key,
            final long streamOffset) throws IOException {
        this(algorithm, CipherStreams.wrapInput(inputStream, bufferSize), cipher, bufferSize, key, streamOffset);
    }

    protected StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm,
            final ReadableByteChannel channel, final ICipher cipher, final int bufferSize, final IKey key,
            final long streamOffset) throws IOException {
        this(algorithm, CipherStreams.wrapInput(channel), cipher, bufferSize, key, streamOffset);
    }

    protected StreamingAsymmetricCipherInputStream(final IAsymmetricCipherAlgorithm algorithm, final ICipherInput input,
            final ICipher cipher, final int bufferSize, final IKey key, final long streamOffset) throws IOException {
        super(algorithm, input, cipher, bufferSize, key);

        resetStreamOffset(streamOffset);
    }

    @Override
    public long skip(final long pN) throws IOException {
        long n = pN;
        Assertions.checkTrue(n >= 0, "Negative skip length.");
        checkStream();

        if (n == 0) {
            return 0;
        } else if (n <= outBuffer.remaining()) {
            final int pos = outBuffer.position() + (int) n;
            ByteBuffers.position(outBuffer, pos);
            return n;
        } else {
            /*
             * Subtract outBuffer.remaining() to see how many bytes we need to skip in the underlying stream. Add
             * outBuffer.remaining() to the actual number of skipped bytes in the underlying stream to get the number of
             * skipped bytes from the user's point of view.
             */
            n -= outBuffer.remaining();
            long skipped = input.skip(n);
            if (skipped < 0) {
                skipped = 0;
            }
            final long pos = streamOffset + skipped;
            skipped += outBuffer.remaining();
            resetStreamOffset(pos);
            return skipped;
        }
    }

    /**
     * Overrides the CtrCipherInputStream.read(ByteBuffer). Reads a sequence of bytes from this channel into the given
     * buffer.
     *
     * @param buf
     *            The buffer into which bytes are to be transferred.
     * @return The number of bytes read, possibly zero, or {@code -1} if the channel has reached end-of-stream.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    public int read(final java.nio.ByteBuffer buf) throws IOException {
        checkStream();
        int unread = outBuffer.remaining();
        if (unread <= 0) { // Fill the unread decrypted data buffer firstly
            final int n = input.read(inBuffer);
            if (n <= 0) {
                return n;
            }

            streamOffset += n; // Read n bytes
            if (buf.isDirect() && buf.remaining() >= inBuffer.position()) {
                // Use buf as the output buffer directly
                decryptInPlace(buf);
                postDecryption();
                return n;
            }
            // Use outBuffer as the output buffer
            decrypt();
            postDecryption();
        }

        // Copy decrypted data from outBuffer to buf
        unread = outBuffer.remaining();
        final int toRead = buf.remaining();
        if (toRead <= unread) {
            final int limit = outBuffer.limit();
            ByteBuffers.limit(outBuffer, outBuffer.position() + toRead);
            buf.put(outBuffer);
            ByteBuffers.limit(outBuffer, limit);
            return toRead;
        }
        buf.put(outBuffer);
        return unread;
    }

    /**
     * Seeks the stream to a specific position relative to start of the under layer stream.
     *
     * @param position
     *            the given position in the data.
     * @throws IOException
     *             if an I/O error occurs.
     */
    public void seek(final long position) throws IOException {
        Assertions.checkTrue(position >= 0, "Cannot seek to negative offset.");
        checkStream();
        /*
         * If data of target pos in the underlying stream has already been read and decrypted in outBuffer, we just need
         * to re-position outBuffer.
         */
        if (position >= getStreamPosition() && position <= getStreamOffset()) {
            final int forward = (int) (position - getStreamPosition());
            if (forward > 0) {
                ByteBuffers.position(outBuffer, outBuffer.position() + forward);
            }
        } else {
            input.seek(position);
            resetStreamOffset(position);
        }
    }

    /**
     * Gets the offset of the stream.
     *
     * @return the stream offset.
     */
    protected long getStreamOffset() {
        return streamOffset;
    }

    /**
     * Sets the offset of stream.
     *
     * @param streamOffset
     *            the stream offset.
     */
    protected void setStreamOffset(final long streamOffset) {
        this.streamOffset = streamOffset;
    }

    /**
     * Gets the position of the stream.
     *
     * @return the position of the stream.
     */
    protected long getStreamPosition() {
        return streamOffset - outBuffer.remaining();
    }

    /**
     * Decrypts more data by reading the under layer stream. The decrypted data will be put in the output buffer.
     *
     * @return The number of decrypted data. -1 if end of the decrypted stream.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    protected int decryptMore() throws IOException {
        final int n = input.read(inBuffer);
        if (n <= 0) {
            return n;
        }

        streamOffset += n; // Read n bytes
        decrypt();
        postDecryption();
        return outBuffer.remaining();
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output. Upon return, inBuffer is cleared; the
     * decrypted data starts at outBuffer.position() and ends at outBuffer.limit().
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    protected void decrypt() throws IOException {
        if (inBuffer.position() == 0) {
            // There is no real data in inBuffer.
            return;
        }

        ByteBuffers.flip(inBuffer);
        outBuffer.clear();
        decryptBuffer(outBuffer);
        inBuffer.clear();
        ByteBuffers.flip(outBuffer);
    }

    /**
     * Does the decryption using inBuffer as input and buf as output. Upon return, inBuffer is cleared; the buf's
     * position will be equal to <i>p</i>&nbsp;{@code +}&nbsp;<i>n</i> where <i>p</i> is the position before decryption,
     * <i>n</i> is the number of bytes decrypted. The buf's limit will not have changed.
     *
     * @param buf
     *            The buffer into which bytes are to be transferred.
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void decryptInPlace(final java.nio.ByteBuffer buf) throws IOException {
        Assertions.checkTrue(buf.isDirect());
        Assertions.checkTrue(buf.remaining() >= inBuffer.position());

        if (inBuffer.position() == 0) {
            // There is no real data in inBuffer.
            return;
        }
        ByteBuffers.flip(inBuffer);
        decryptBuffer(buf);
        inBuffer.clear();
    }

    /**
     * Decrypts all data in buf: total n bytes from given start position. Output is also buf and same start position.
     * buf.position() and buf.limit() should be unchanged after decryption.
     *
     * @param buf
     *            The buffer into which bytes are to be transferred.
     * @param offset
     *            the start offset in the data.
     * @param len
     *            the maximum number of decrypted data bytes to read.
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void decrypt(final java.nio.ByteBuffer buf, final int offset, final int len) throws IOException {
        final int pos = buf.position();
        final int limit = buf.limit();
        int n = 0;
        while (n < len) {
            ByteBuffers.position(buf, offset + n);
            ByteBuffers.limit(buf, offset + n + Math.min(len - n, inBuffer.remaining()));
            inBuffer.put(buf);
            // Do decryption
            try {
                decrypt();
                ByteBuffers.position(buf, offset + n);
                ByteBuffers.limit(buf, limit);
                n += outBuffer.remaining();
                buf.put(outBuffer);
            } finally {
                postDecryption();
            }
        }
        ByteBuffers.position(buf, pos);
    }

    /**
     * This method is executed immediately after decryption. Checks whether cipher should be updated.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void postDecryption() throws IOException {
        if (cipherReset) {
            /*
             * This code is generally not executed since the cipher usually maintains cipher context (e.g. the counter)
             * internally. However, some implementations can't maintain context so a re-init is necessary after each
             * decryption call.
             */
            resetCipher();
        }
    }

    /**
     * Calculates the counter and iv, resets the cipher.
     *
     * @param position
     *            the given position in the data.
     * @throws IOException
     *             if an I/O error occurs.
     */
    @SuppressWarnings("deprecation")
    protected void resetCipher() throws IOException {
        try {
            cipher.init(CipherMode.Decrypt, key, params);
        } catch (final Exception e) {
            throw new IOException(e);
        }
        cipherReset = false;
    }

    /**
     * Resets the underlying stream offset; clear {@link #inBuffer} and {@link #outBuffer}. This Typically happens
     * during {@link #skip(long)}.
     *
     * @param offset
     *            the offset of the stream.
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void resetStreamOffset(final long offset) throws IOException {
        streamOffset = offset;
        inBuffer.clear();
        outBuffer.clear();
        ByteBuffers.limit(outBuffer, 0);
        if (offset != 0) {
            resetCipher();
        }
    }

    /**
     * Does the decryption using out as output.
     *
     * @param out
     *            the output ByteBuffer.
     * @throws IOException
     *             if an I/O error occurs.
     */
    protected void decryptBuffer(final java.nio.ByteBuffer out) throws IOException {
        final int inputSize = inBuffer.remaining();
        try {
            final int n = cipher.update(inBuffer, out);
            if (n < inputSize) {
                /**
                 * Typically code will not get here. ICipher#update will consume all input data and put result in
                 * outBuffer. ICipher#doFinal will reset the cipher context.
                 */
                cipher.doFinal(inBuffer, out);
                cipherReset = true;
            }
        } catch (final Exception e) {
            throw new IOException(e);
        }
    }

}
