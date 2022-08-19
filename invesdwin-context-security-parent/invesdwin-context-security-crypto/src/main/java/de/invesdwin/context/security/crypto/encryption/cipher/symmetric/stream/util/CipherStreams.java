package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

import javax.annotation.concurrent.Immutable;

import org.agrona.BufferUtil;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input.ChannelCipherInput;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input.ICipherInput;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input.StreamCipherInput;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output.ChannelCipherOutput;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output.ICipherOutput;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output.StreamCipherOutput;
import de.invesdwin.util.assertions.Assertions;

@Immutable
public final class CipherStreams {

    public static final int DEFAULT_STREAM_BUFFER_SIZE = 8192;

    public static final int MIN_BUFFER_SIZE = 512;

    private CipherStreams() {}

    public static ICipherInput wrapInput(final InputStream in, final int bufferSize) {
        if (in instanceof ReadableByteChannel) {
            final ReadableByteChannel cIn = (ReadableByteChannel) in;
            return wrapInput(cIn);
        } else {
            return new StreamCipherInput(in, bufferSize);
        }
    }

    public static ICipherInput wrapInput(final ReadableByteChannel in) {
        return new ChannelCipherInput(in);
    }

    public static ICipherOutput wrapOutput(final OutputStream out, final int bufferSize) {
        if (out instanceof WritableByteChannel) {
            final WritableByteChannel cOut = (WritableByteChannel) out;
            return wrapOutput(cOut);
        } else {
            return new StreamCipherOutput(out, bufferSize);
        }
    }

    public static ICipherOutput wrapOutput(final WritableByteChannel out) {
        return new ChannelCipherOutput(out);
    }

    public static void freeDirectBuffer(final java.nio.ByteBuffer buffer) {
        BufferUtil.free(buffer);
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
        Assertions.checkTrue(bufferSize >= MIN_BUFFER_SIZE, "Minimum value of buffer size is " + MIN_BUFFER_SIZE + ".");
        final int blockSize = cipher.getBlockSize();
        if (blockSize == 0) {
            return bufferSize;
        } else {
            return bufferSize - bufferSize % blockSize;
        }
    }

}
