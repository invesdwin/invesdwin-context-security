package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

import javax.annotation.concurrent.Immutable;

import org.agrona.BufferUtil;
import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;
import org.apache.commons.crypto.utils.Utils;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.system.properties.SystemProperties;

@Immutable
public final class CipherStreams {

    /**
     * The configuration key of the buffer size for stream.
     */
    public static final String STREAM_BUFFER_SIZE_KEY = Crypto.CONF_PREFIX + "stream.buffer.size";

    // stream related configuration keys
    /**
     * The default value of the buffer size for stream.
     */
    public static final int STREAM_BUFFER_SIZE_DEFAULT = 8192;

    public static final int MIN_BUFFER_SIZE = 512;

    private CipherStreams() {
    }

    public static Input wrapInput(final InputStream in, final int bufferSize) {
        if (in instanceof ReadableByteChannel) {
            final ReadableByteChannel cIn = (ReadableByteChannel) in;
            return wrapInput(cIn);
        } else {
            return new StreamInput(in, bufferSize);
        }
    }

    public static Input wrapInput(final ReadableByteChannel in) {
        return new ChannelInput(in);
    }

    public static Output wrapOutput(final OutputStream out, final int bufferSize) {
        if (out instanceof WritableByteChannel) {
            final WritableByteChannel cOut = (WritableByteChannel) out;
            return wrapOutput(cOut);
        } else {
            return new StreamOutput(out, bufferSize);
        }
    }

    public static Output wrapOutput(final WritableByteChannel out) {
        return new ChannelOutput(out);
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
        final String bufferSizeStr = SystemProperties.SYSTEM_PROPERTIES.getProperty(STREAM_BUFFER_SIZE_KEY);
        if (bufferSizeStr == null || bufferSizeStr.isEmpty()) {
            return STREAM_BUFFER_SIZE_DEFAULT;
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
        Utils.checkArgument(bufferSize >= MIN_BUFFER_SIZE, "Minimum value of buffer size is " + MIN_BUFFER_SIZE + ".");
        return bufferSize - bufferSize % cipher.getBlockSize();
    }

}
