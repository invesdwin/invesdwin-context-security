package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output;

import java.io.IOException;
import java.nio.channels.WritableByteChannel;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * Adapted from: org.apache.commons.crypto.stream.output.ChannelOutput
 */
@NotThreadSafe
public class ChannelCipherOutput implements ICipherOutput {

    private final WritableByteChannel channel;

    public ChannelCipherOutput(final WritableByteChannel channel) {
        this.channel = channel;
    }

    @Override
    public int write(final java.nio.ByteBuffer src) throws IOException {
        return channel.write(src);
    }

    @Override
    public void flush() throws IOException {
        // noop
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
