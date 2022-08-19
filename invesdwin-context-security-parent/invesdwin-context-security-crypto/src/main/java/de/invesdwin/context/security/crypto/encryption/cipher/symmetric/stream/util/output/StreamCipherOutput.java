package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output;

import java.io.IOException;
import java.io.OutputStream;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Adapted from: org.apache.commons.crypto.stream.output.StreamOutput
 */
@NotThreadSafe
public class StreamCipherOutput implements ICipherOutput {
    private final byte[] buf;
    private final int bufferSize;
    private final OutputStream out;

    public StreamCipherOutput(final OutputStream out, final int bufferSize) {
        this.out = out;
        this.bufferSize = bufferSize;
        buf = new byte[bufferSize];
    }

    @Override
    public int write(final java.nio.ByteBuffer src) throws IOException {
        final int len = src.remaining();

        int remaining = len;
        while (remaining > 0) {
            final int n = Math.min(remaining, bufferSize);
            src.get(buf, 0, n);
            out.write(buf, 0, n);
            remaining = src.remaining();
        }

        return len;
    }

    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        out.close();
    }

    protected OutputStream getOut() {
        return out;
    }
}
