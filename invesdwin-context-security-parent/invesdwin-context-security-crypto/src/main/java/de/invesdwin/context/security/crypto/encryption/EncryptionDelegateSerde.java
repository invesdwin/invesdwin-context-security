package de.invesdwin.context.security.crypto.encryption;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.marshallers.serde.SerdeBaseMethods;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class EncryptionDelegateSerde<E> implements ISerde<E> {

    private final ISerde<E> delegate;
    private final IEncryptionFactory encryptionFactory;

    /**
     * WARNING: for internal use only. Use maybeWrap() instead.
     */
    @Deprecated
    public EncryptionDelegateSerde(final ISerde<E> delegate, final IEncryptionFactory encryptionFactory) {
        Assertions.assertThat(delegate).isNotInstanceOf(EncryptionDelegateSerde.class);
        this.delegate = delegate;
        this.encryptionFactory = encryptionFactory;
    }

    @Override
    public E fromBytes(final byte[] bytes) {
        return SerdeBaseMethods.fromBytes(this, bytes);
    }

    @Override
    public byte[] toBytes(final E obj) {
        return SerdeBaseMethods.toBytes(this, obj);
    }

    @Override
    public E fromBuffer(final IByteBuffer buffer, final int length) {
        if (length == 0) {
            return null;
        }
        if (encryptionFactory == DisabledEncryptionFactory.INSTANCE) {
            //we can save a copy here
            return delegate.fromBuffer(buffer, length);
        } else {
            final IByteBuffer decryptedBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
            try {
                final int decryptedLength = encryptionFactory.encrypt(buffer, decryptedBuffer);
                final E copied = delegate.fromBuffer(decryptedBuffer, decryptedLength);
                //                decryptedBuffer.clear(Bytes.ZERO, 0, decryptedLength);
                return copied;
            } finally {
                ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedBuffer);
            }
        }
    }

    @Override
    public int toBuffer(final IByteBuffer buffer, final E obj) {
        if (obj == null) {
            return 0;
        }
        if (encryptionFactory == DisabledEncryptionFactory.INSTANCE) {
            //we can save a copy here
            return delegate.toBuffer(buffer, obj);
        } else {
            final IByteBuffer decryptedBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
            try {
                final int decryptedLength = delegate.toBuffer(decryptedBuffer, obj);
                final int copied = encryptionFactory.decrypt(decryptedBuffer.sliceTo(decryptedLength), buffer);
                //                decryptedBuffer.clear(Bytes.ZERO, 0, decryptedLength);
                return copied;
            } finally {
                ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedBuffer);
            }
        }
    }

    public static <T> ISerde<T> maybeWrap(final ISerde<T> delegate, final IEncryptionFactory encryptionFactory) {
        return encryptionFactory.maybeWrap(delegate);
    }

}
