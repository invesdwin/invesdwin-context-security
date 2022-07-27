package de.invesdwin.context.security.crypto.verification.hash.stream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.ReadableByteChannel;
import java.security.Key;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;

@NotThreadSafe
public class ChannelLayeredHashInputStream extends LayeredHashInputStream implements ReadableByteChannel {

    private final ReadableByteChannel delegateChannel;

    public ChannelLayeredHashInputStream(final InputStream delegate, final IHash hash, final Key key) {
        super(delegate, hash, key);
        this.delegateChannel = (ReadableByteChannel) delegate;
    }

    @Override
    public boolean isOpen() {
        return delegateChannel.isOpen();
    }

    @Override
    public int read(final java.nio.ByteBuffer dst) throws IOException {
        final int positionBefore = dst.position();
        final int length = delegateChannel.read(dst);
        hash.update(ByteBuffers.wrap(dst, positionBefore, length));
        return length;
    }

    public static LayeredHashInputStream maybeWrap(final InputStream delegate, final IHash hash, final Key key) {
        if (delegate instanceof ReadableByteChannel) {
            return new ChannelLayeredHashInputStream(delegate, hash, key);
        } else {
            return new LayeredHashInputStream(delegate, hash, key);
        }
    }

}
