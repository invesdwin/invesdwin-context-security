package de.invesdwin.context.security.crypto.key;

import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IKey {

    /**
     * This is the number of bytes of the key (e.g. 128/256 for AES or 4096 for RSA)
     */
    int getKeySize();

    /**
     * This is the size in bytes for this key instance. This combines the primary key with e.g. a secondary key or IV.
     */
    int getKeyBlockSize();

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

    <T> T unwrap(Class<T> type);

}
