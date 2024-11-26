package de.invesdwin.context.security.crypto.key;

import de.invesdwin.norva.beanpath.spi.IUnwrap;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.ICloseableByteBuffer;

public interface IKey extends IUnwrap {

    /**
     * This is the number of bytes of the key (e.g. 128/256 for AES or 4096 for RSA)
     */
    int getKeySizeBits();

    /**
     * This is the size in bytes for this key instance. This combines the primary key with e.g. a secondary key or IV.
     */
    int getKeyBlockSize();

    default byte[] toBytes() {
        try (ICloseableByteBuffer buffer = ByteBuffers.EXPANDABLE_POOL.borrowObject()) {
            final int length = toBuffer(buffer);
            return buffer.asByteArrayCopyTo(length);
        }
    }

    default IKey fromBytes(final byte[] bytes) {
        return fromBuffer(ByteBuffers.wrap(bytes));
    }

    int toBuffer(IByteBuffer buffer);

    IKey fromBuffer(IByteBuffer buffer);

    IKey newRandomInstance();

}
