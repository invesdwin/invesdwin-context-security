package de.invesdwin.context.security.crypto.encryption;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.marshallers.serde.SerdeBaseMethods;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class EncryptionDelegateSerde<E> implements ISerde<E> {

    private final ISerde<E> delegate;
    private final IEncryptionFactory encryptionFactory;
    private final IKey key;

    /**
     * WARNING: for internal use only. Use maybeWrap() instead.
     */
    @Deprecated
    public EncryptionDelegateSerde(final ISerde<E> delegate, final IEncryptionFactory encryptionFactory,
            final IKey key) {
        Assertions.assertThat(delegate).isNotInstanceOf(EncryptionDelegateSerde.class);
        this.delegate = delegate;
        this.encryptionFactory = encryptionFactory;
        this.key = key;
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
    public E fromBuffer(final IByteBuffer buffer) {
        if (buffer.capacity() == 0) {
            return null;
        }
        if (encryptionFactory == DisabledEncryptionFactory.INSTANCE) {
            //we can save a copy here
            return delegate.fromBuffer(buffer);
        } else {
            final IByteBuffer decryptedBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
            final ICipher cipher = encryptionFactory.getCipherPool().borrowObject();
            try {
                final int decryptedLength = encryptionFactory.encrypt(buffer, decryptedBuffer, cipher, key);
                final E copied = delegate.fromBuffer(decryptedBuffer.sliceTo(decryptedLength));
                //                decryptedBuffer.clear(Bytes.ZERO, 0, decryptedLength);
                return copied;
            } finally {
                encryptionFactory.getCipherPool().returnObject(cipher);
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
            final ICipher cipher = encryptionFactory.getCipherPool().borrowObject();
            try {
                final int decryptedLength = delegate.toBuffer(decryptedBuffer, obj);
                final int copied = encryptionFactory.decrypt(decryptedBuffer.sliceTo(decryptedLength), buffer, cipher,
                        key);
                //                decryptedBuffer.clear(Bytes.ZERO, 0, decryptedLength);
                return copied;
            } finally {
                encryptionFactory.getCipherPool().returnObject(cipher);
                ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedBuffer);
            }
        }
    }

}
