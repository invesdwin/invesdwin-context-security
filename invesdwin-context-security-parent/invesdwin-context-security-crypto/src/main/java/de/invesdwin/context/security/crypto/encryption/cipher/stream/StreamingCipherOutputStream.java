package de.invesdwin.context.security.crypto.encryption.cipher.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import org.apache.commons.crypto.stream.CryptoOutputStream;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;
import org.apache.commons.crypto.utils.Utils;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;

/**
 * <p>
 * CtrCryptoOutputStream encrypts data. It is not thread-safe. AES CTR mode is required in order to ensure that the
 * plain text and cipher text have a 1:1 mapping. The encryption is buffer based. The key points of the encryption are
 * (1) calculating counter and (2) padding through stream position.
 * </p>
 * <p>
 * counter = base + pos/(algorithm blocksize); padding = pos%(algorithm blocksize);
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
public class StreamingCipherOutputStream extends CipherOutputStream {
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
     * Padding = pos%(algorithm blocksize); Padding is put into {@link #inBuffer} before any other data goes in. The
     * purpose of padding is to put input data at proper position.
     */
    private byte padding;

    /**
     * Flag to mark whether the cipher has been reset
     */
    private boolean cipherReset = false;

    public StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final OutputStream out, final byte[] key,
            final byte[] iv) throws IOException {
        this(algorithm, out, key, iv, 0);
    }

    public StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final WritableByteChannel out,
            final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, out, key, iv, 0);
    }

    protected StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final OutputStream out,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, out, cipher, bufferSize, key, iv, 0);
    }

    protected StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final WritableByteChannel channel,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, channel, cipher, bufferSize, key, iv, 0);
    }

    protected StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final Output output, final ICipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(algorithm, output, cipher, bufferSize, key, iv, 0);
    }

    public StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final OutputStream outputStream,
            final byte[] key, final byte[] iv, final long streamOffset) throws IOException {
        this(algorithm, outputStream, algorithm.newCipher(), CipherInputStream.getDefaultBufferSize(), key, iv,
                streamOffset);
    }

    public StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final WritableByteChannel channel,
            final byte[] key, final byte[] iv, final long streamOffset) throws IOException {
        this(algorithm, channel, algorithm.newCipher(), CipherInputStream.getDefaultBufferSize(), key, iv,
                streamOffset);
    }

    protected StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final OutputStream outputStream,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(algorithm, new StreamOutput(outputStream, bufferSize), cipher, bufferSize, key, iv, streamOffset);
    }

    protected StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final WritableByteChannel channel,
            final ICipher cipher, final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(algorithm, new ChannelOutput(channel), cipher, bufferSize, key, iv, streamOffset);
    }

    protected StreamingCipherOutputStream(final ICipherAlgorithm algorithm, final Output output, final ICipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset) throws IOException {
        super(algorithm, output, cipher, bufferSize, key, iv);

        this.streamOffset = streamOffset;
        this.initIV = iv.clone();
        this.iv = new MutableIvParameterSpec(iv.clone());

        resetCipher();
    }

    /**
     * Does the encryption, input is {@link #inBuffer} and output is {@link #outBuffer}.
     *
     * @throws IOException
     *             if an I/O error occurs.
     */
    @Override
    protected void encrypt() throws IOException {
        Utils.checkState(inBuffer.position() >= padding);
        if (inBuffer.position() == padding) {
            // There is no real data in the inBuffer.
            return;
        }

        inBuffer.flip();
        outBuffer.clear();
        encryptBuffer(outBuffer);
        inBuffer.clear();
        outBuffer.flip();

        if (padding > 0) {
            /*
             * The plain text and cipher text have a 1:1 mapping, they start at the same position.
             */
            outBuffer.position(padding);
            padding = 0;
        }

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

    /**
     * Overrides the {@link CryptoOutputStream#initCipher()}. Initializes the cipher.
     */
    @Override
    protected void initCipher() {
        // Do nothing for initCipher
        // Will reset the cipher considering the stream offset
    }

    /**
     * Resets the {@link #cipher}: calculate counter and {@link #padding}.
     *
     */
    private void resetCipher() {
        final long counter = streamOffset / cipher.getBlockSize();
        padding = (byte) (streamOffset % cipher.getBlockSize());
        inBuffer.position(padding); // Set proper position for input data.

        CipherDerivedIV.calculateIV(initIV, counter, iv.getIV());
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithm.wrapIv(iv));
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
        final int n = cipher.update(inBuffer, out);
        if (n < inputSize) {
            /**
             * Typically code will not get here. ICipher#update will consume all input data and put result in outBuffer.
             * ICipher#doFinal will reset the cipher context.
             */
            cipher.doFinal(inBuffer, out);
            cipherReset = true;
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
