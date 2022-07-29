package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;
import java.security.PublicKey;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import org.apache.commons.crypto.stream.output.Output;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.CipherStreams;

@NotThreadSafe
public class StreamingAsymmetricCipherOutputStream extends AsymmetricCipherOutputStream {
    /**
     * Underlying stream offset.
     */
    private long streamOffset = 0;

    /**
     * Flag to mark whether the cipher has been reset
     */
    private boolean cipherReset = false;

    public StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final OutputStream out,
            final PublicKey key) throws IOException {
        this(algorithm, out, key, 0);
    }

    public StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final WritableByteChannel out, final PublicKey key) throws IOException {
        this(algorithm, out, key, 0);
    }

    public StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final OutputStream out,
            final ICipher cipher, final PublicKey key) throws IOException {
        this(algorithm, out, cipher, CipherStreams.getDefaultBufferSize(), key, 0);
    }

    public StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final PublicKey key) throws IOException {
        this(algorithm, channel, cipher, CipherStreams.getDefaultBufferSize(), key, 0);
    }

    protected StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final OutputStream out,
            final ICipher cipher, final int bufferSize, final PublicKey key) throws IOException {
        this(algorithm, out, cipher, bufferSize, key, 0);
    }

    protected StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final int bufferSize, final PublicKey key)
            throws IOException {
        this(algorithm, channel, cipher, bufferSize, key, 0);
    }

    protected StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final Output output,
            final ICipher cipher, final int bufferSize, final PublicKey key) throws IOException {
        this(algorithm, output, cipher, bufferSize, key, 0);
    }

    public StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final OutputStream outputStream, final PublicKey key, final long streamOffset) throws IOException {
        this(algorithm, outputStream, algorithm.newCipher(), CipherStreams.getDefaultBufferSize(), key, streamOffset);
    }

    public StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final PublicKey key, final long streamOffset) throws IOException {
        this(algorithm, channel, algorithm.newCipher(), CipherStreams.getDefaultBufferSize(), key, streamOffset);
    }

    protected StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final OutputStream outputStream, final ICipher cipher, final int bufferSize, final PublicKey key,
            final long streamOffset) throws IOException {
        this(algorithm, CipherStreams.wrapOutput(outputStream, bufferSize), cipher, bufferSize, key, streamOffset);
    }

    protected StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm,
            final WritableByteChannel channel, final ICipher cipher, final int bufferSize, final PublicKey key,
            final long streamOffset) throws IOException {
        this(algorithm, CipherStreams.wrapOutput(channel), cipher, bufferSize, key, streamOffset);
    }

    protected StreamingAsymmetricCipherOutputStream(final IAsymmetricCipherAlgorithm algorithm, final Output output,
            final ICipher cipher, final int bufferSize, final PublicKey key, final long streamOffset)
            throws IOException {
        super(algorithm, output, cipher, bufferSize, key);

        this.streamOffset = streamOffset;

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

    private void resetCipher() throws IOException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
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
