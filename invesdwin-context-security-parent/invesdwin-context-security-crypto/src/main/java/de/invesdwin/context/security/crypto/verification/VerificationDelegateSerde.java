package de.invesdwin.context.security.crypto.verification;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.marshallers.serde.SerdeBaseMethods;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class VerificationDelegateSerde<E> implements ISerde<E> {

    private final ISerde<E> delegate;
    private final IVerificationFactory verificationFactory;
    private final IKey key;

    /**
     * WARNING: for internal use only. Use maybeWrap() instead.
     */
    @Deprecated
    public VerificationDelegateSerde(final ISerde<E> delegate, final IVerificationFactory verificationFactory,
            final IKey key) {
        Assertions.assertThat(delegate).isNotInstanceOf(VerificationDelegateSerde.class);
        this.delegate = delegate;
        this.verificationFactory = verificationFactory;
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
    public E fromBuffer(final IByteBuffer buffer, final int length) {
        if (length == 0) {
            return null;
        }
        if (verificationFactory == DisabledVerificationFactory.INSTANCE) {
            //we can save a copy here
            return delegate.fromBuffer(buffer, length);
        } else {
            final IHash hash = verificationFactory.getHashPool().borrowObject();
            try {
                final IByteBuffer verifiedBuffer = verificationFactory.verifyAndSlice(buffer.sliceTo(length), hash,
                        key);
                return delegate.fromBuffer(verifiedBuffer, verifiedBuffer.capacity());
            } finally {
                verificationFactory.getHashPool().returnObject(hash);
            }
        }
    }

    @Override
    public int toBuffer(final IByteBuffer buffer, final E obj) {
        if (obj == null) {
            return 0;
        }
        if (verificationFactory == DisabledVerificationFactory.INSTANCE) {
            //we can save a copy here
            return delegate.toBuffer(buffer, obj);
        } else {
            final IHash hash = verificationFactory.getHashPool().borrowObject();
            try {
                final int signatureIndex = delegate.toBuffer(buffer, obj);
                final int signatureLength = verificationFactory.putHash(buffer, signatureIndex, hash, key);
                return signatureIndex + signatureLength;
            } finally {
                verificationFactory.getHashPool().returnObject(hash);
            }
        }
    }

}
