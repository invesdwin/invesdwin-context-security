package de.invesdwin.context.security.crypto.verification.hash.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.WritableByteChannel;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;

@NotThreadSafe
public class ChannelLayeredHashOutputStream extends LayeredHashOutputStream implements WritableByteChannel {

    private final WritableByteChannel delegateChannel;

    public ChannelLayeredHashOutputStream(final OutputStream delegate, final IHash hash, final IKey key) {
        super(delegate, hash, key);
        this.delegateChannel = (WritableByteChannel) delegate;
    }

    @Override
    public boolean isOpen() {
        return delegateChannel.isOpen();
    }

    @Override
    public int write(final java.nio.ByteBuffer src) throws IOException {
        final int positionBefore = src.position();
        final int length = delegateChannel.write(src);
        hash.update(ByteBuffers.wrap(src, positionBefore, length));
        return length;
    }

    public static LayeredHashOutputStream maybeWrap(final OutputStream delegate, final IHash hash, final IKey key) {
        if (delegate instanceof WritableByteChannel) {
            return new ChannelLayeredHashOutputStream(delegate, hash, key);
        } else {
            return new LayeredHashOutputStream(delegate, hash, key);
        }
    }

}
