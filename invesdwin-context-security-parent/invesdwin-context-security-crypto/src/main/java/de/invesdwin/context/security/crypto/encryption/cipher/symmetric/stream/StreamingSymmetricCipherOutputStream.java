package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.CipherStreams;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output.ICipherOutput;
import de.invesdwin.context.security.crypto.key.IKey;

/**
 * <p>
 * CtrCryptoOutputStream encrypts data. It is not thread-safe. AES CTR mode is required in order to ensure that the
 * plain text and cipher text have a 1:1 mapping. The encryption is buffer based. The key point of the encryption is
 * calculating counter.
 * </p>
 * <p>
 * counter = base + pos/(algorithm blocksize);
 * </p>
 * <p>
 * The underlying stream offset is maintained as state.
 * </p>
 * <p>
 * This class should only be used with blocking sinks. Using this class to wrap a non-blocking sink may lead to high CPU
 * usage.
 * </p>
 * 
 * Adapted from: org.apache.commons.crypto.stream.CtrCryptoOutputStream
 */
@NotThreadSafe
public class StreamingSymmetricCipherOutputStream extends SymmetricCipherOutputStream {
    /**
     * Underlying stream offset.
     */
    private long streamOffset = 0;

    /**
     * The initial IV.
     */
    private final byte[] initIV;

    /**
     * Initialization vector for the cipher.
     */
    private final MutableIvParameterSpec iv;

    /**
     * Flag to mark whether the cipher has been reset
     */
    private boolean cipherReset = false;

    public StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm, final OutputStream out,
            final IKey key, final byte[] iv) throws IOException {
        this(algorithm, out, key, iv, 0);
    }

    public StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final WritableByteChannel out, final IKey key, final byte[] iv) throws IOException {
        this(algorithm, out, key, iv, 0);
    }

    public StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm, final OutputStream out,
            final ICipher cipher, final IKey key, final byte[] iv) throws IOException {
        this(algorithm, out, cipher, CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, iv, 0);
    }

    public StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final IKey key, final byte[] iv)
            throws IOException {
        this(algorithm, channel, cipher, CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, iv, 0);
    }

    protected StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm, final OutputStream out,
            final ICipher cipher, final int bufferSize, final IKey key, final byte[] iv) throws IOException {
        this(algorithm, out, cipher, bufferSize, key, iv, 0);
    }

    protected StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final int bufferSize, final IKey key,
            final byte[] iv) throws IOException {
        this(algorithm, channel, cipher, bufferSize, key, iv, 0);
    }

    protected StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final ICipherOutput output, final ICipher cipher, final int bufferSize, final IKey key, final byte[] iv)
            throws IOException {
        this(algorithm, output, cipher, bufferSize, key, iv, 0);
    }

    public StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final OutputStream outputStream, final IKey key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(algorithm, outputStream, algorithm.newCipher(), CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, iv,
                streamOffset);
    }

    public StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final IKey key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(algorithm, channel, algorithm.newCipher(), CipherStreams.DEFAULT_STREAM_BUFFER_SIZE, key, iv,
                streamOffset);
    }

    protected StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final OutputStream outputStream, final ICipher cipher, final int bufferSize, final IKey key,
            final byte[] iv, final long streamOffset) throws IOException {
        this(algorithm, CipherStreams.wrapOutput(outputStream, bufferSize), cipher, bufferSize, key, iv, streamOffset);
    }

    protected StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final int bufferSize, final IKey key,
            final byte[] iv, final long streamOffset) throws IOException {
        this(algorithm, CipherStreams.wrapOutput(channel), cipher, bufferSize, key, iv, streamOffset);
    }

    protected StreamingSymmetricCipherOutputStream(final ISymmetricCipherAlgorithm algorithm,
            final ICipherOutput output, final ICipher cipher, final int bufferSize, final IKey key, final byte[] iv,
            final long streamOffset) throws IOException {
        super(algorithm, output, cipher, bufferSize, key, iv);

        this.streamOffset = streamOffset;
        this.initIV = iv.clone();
        this.iv = new MutableIvParameterSpec(iv.clone());

        if (streamOffset != 0) {
            resetCipher();
        }
    }

    /**
     * Does the encryption, input is {@link #inBuffer} and output is {@link #outBuffer}.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    protected void encrypt() throws IOException {
        if (inBuffer.position() == 0) {
            // There is no real data in the inBuffer.
            return;
        }

        inBuffer.flip();
        outBuffer.clear();
        encryptBuffer(outBuffer);
        inBuffer.clear();
        outBuffer.flip();

        final int len = output.write(outBuffer);
        streamOffset += len;
        if (cipherReset) {
            /*
             * This code is generally not executed since the encryptor usually maintains encryption context (e.g. the
             * counter) internally. However, some implementations can't maintain context so a re-init is necessary after
             * each encryption call.
             */
            resetCipher();
        }
    }

    /**
     * Does final encryption of the last data.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    protected void encryptFinal() throws IOException {
        // The same as the normal encryption for Counter mode
        encrypt();
    }

    @SuppressWarnings("deprecation")
    private void resetCipher() throws IOException {
        final long counter = streamOffset / cipher.getBlockSize();

        CipherDerivedIV.calculateIV(initIV, counter, iv.getIV());
        try {
            cipher.init(CipherMode.Encrypt, key, algorithm.wrapParam(iv));
        } catch (final Exception e) {
            throw new IOException(e);
        }
        cipherReset = false;
    }

    /**
     * Does the encryption if the ByteBuffer data.
     *
     * @param out
     *            the output ByteBuffer.
     * @throws IOException
     *             if an I/O error occurs.
     */
    private void encryptBuffer(final java.nio.ByteBuffer out) throws IOException {
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

    /**
     * Get the underlying stream offset
     *
     * @return the underlying stream offset
     */
    protected long getStreamOffset() {
        return streamOffset;
    }

    /**
     * Set the underlying stream offset
     *
     * @param streamOffset
     *            the underlying stream offset
     */
    protected void setStreamOffset(final long streamOffset) {
        this.streamOffset = streamOffset;
    }
}
