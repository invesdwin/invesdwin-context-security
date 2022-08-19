package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input;

import java.io.IOException;
import java.io.InputStream;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Adapted from: org.apache.commons.crypto.stream.input.StreamInput
 */
@NotThreadSafe
public class StreamCipherInput implements ICipherInput {
    private final byte[] buf;
    private final int bufferSize;
    private final InputStream in;

    public StreamCipherInput(final InputStream inputStream, final int bufferSize) {
        this.in = inputStream;
        this.bufferSize = bufferSize;
        buf = new byte[bufferSize];
    }

    @Override
    public int read(final java.nio.ByteBuffer dst) throws IOException {
        int remaining = dst.remaining();
        int read = 0;
        while (remaining > 0) {
            final int n = in.read(buf, 0, Math.min(remaining, bufferSize));
            if (n == -1) {
                if (read == 0) {
                    read = -1;
                }
                break;
            } else if (n > 0) {
                dst.put(buf, 0, n);
                read += n;
                remaining -= n;
            }
        }
        return read;
    }

    @Override
    public long skip(final long n) throws IOException {
        return in.skip(n);
    }

    @Override
    public int available() throws IOException {
        return in.available();
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
        in.close();
    }
}
