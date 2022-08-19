package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input;

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Adapted from: org.apache.commons.crypto.stream.input.ChannelInput
 */
@NotThreadSafe
public class ChannelCipherInput implements ICipherInput {
    private static final int SKIP_BUFFER_SIZE = 2048;

    private java.nio.ByteBuffer buf;
    private final ReadableByteChannel channel;

    public ChannelCipherInput(final ReadableByteChannel channel) {
        this.channel = channel;
    }

    @Override
    public int read(final java.nio.ByteBuffer dst) throws IOException {
        return channel.read(dst);
    }

    @Override
    public long skip(final long n) throws IOException {
        long remaining = n;
        int nr;

        if (n <= 0) {
            return 0;
        }

        final int size = (int) Math.min(SKIP_BUFFER_SIZE, remaining);
        final java.nio.ByteBuffer skipBuffer = getSkipBuf();
        while (remaining > 0) {
            skipBuffer.clear();
            skipBuffer.limit((int) Math.min(size, remaining));
            nr = read(skipBuffer);
            if (nr < 0) {
                break;
            }
            remaining -= nr;
        }

        return n - remaining;
    }

    @Override
    public int available() throws IOException {
        return 0;
    }

    @Override
    public int read(final long position, final byte[] buffer, final int offset, final int length) throws IOException {
        throw new UnsupportedOperationException("Positioned read is not supported by this implementation");
    }

    @Override
    public void seek(final long position) throws IOException {
        throw new UnsupportedOperationException("Seek is not supported by this implementation");
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    private java.nio.ByteBuffer getSkipBuf() {
        if (buf == null) {
            buf = java.nio.ByteBuffer.allocate(SKIP_BUFFER_SIZE);
        }
        return buf;
    }
}
