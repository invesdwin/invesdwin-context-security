package de.invesdwin.context.security.crypto.key;

import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IKey {

    int getKeySize();

    default byte[] toBytes() {
        final IByteBuffer buffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
        try {
            final int length = toBuffer(buffer);
            return buffer.asByteArrayCopyTo(length);
        } finally {
            ByteBuffers.EXPANDABLE_POOL.returnObject(buffer);
        }
    }

    default IKey fromBytes(final byte[] bytes) {
        return fromBuffer(ByteBuffers.wrap(bytes));
    }

    int toBuffer(IByteBuffer buffer);

    IKey fromBuffer(IByteBuffer buffer);

    IKey newRandomInstance();

}
