package de.invesdwin.context.security.crypto.authentication;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.marshallers.serde.SerdeBaseMethods;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class AuthenticationDelegateSerde<E> implements ISerde<E> {

    private final ISerde<E> delegate;
    private final IAuthenticationFactory authenticationFactory;

    /**
     * WARNING: for internal use only. Use maybeWrap() instead.
     */
    @Deprecated
    public AuthenticationDelegateSerde(final ISerde<E> delegate, final IAuthenticationFactory authenticationFactory) {
        Assertions.assertThat(delegate).isNotInstanceOf(AuthenticationDelegateSerde.class);
        this.delegate = delegate;
        this.authenticationFactory = authenticationFactory;
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
        if (authenticationFactory == DisabledAuthenticationFactory.INSTANCE) {
            //we can save a copy here
            return delegate.fromBuffer(buffer, length);
        } else {
            final IByteBuffer verifiedBuffer = authenticationFactory.verifyAndSlice(buffer.sliceTo(length));
            return delegate.fromBuffer(verifiedBuffer, verifiedBuffer.capacity());
        }
    }

    @Override
    public int toBuffer(final IByteBuffer buffer, final E obj) {
        if (obj == null) {
            return 0;
        }
        if (authenticationFactory == DisabledAuthenticationFactory.INSTANCE) {
            //we can save a copy here
            return delegate.toBuffer(buffer, obj);
        } else {
            final int signatureIndex = delegate.toBuffer(buffer, obj);
            final int signatureLength = authenticationFactory.putSignature(buffer, signatureIndex);
            return signatureIndex + signatureLength;
        }
    }

    public static <T> ISerde<T> maybeWrap(final ISerde<T> delegate,
            final IAuthenticationFactory authenticationFactory) {
        return authenticationFactory.maybeWrap(delegate);
    }

}
