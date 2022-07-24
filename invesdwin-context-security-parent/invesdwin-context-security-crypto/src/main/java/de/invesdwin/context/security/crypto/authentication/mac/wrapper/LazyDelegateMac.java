package de.invesdwin.context.security.crypto.authentication.mac.wrapper;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class LazyDelegateMac implements IMac {

    private final IMac delegate;
    private boolean needsReset;
    /**
     * Not storing identity here because this might cause collisions if the object is already released. Instead using
     * close() to clear up the reference.
     */
    private Key prevKey;

    public LazyDelegateMac(final IMac delegate) {
        this.delegate = delegate;
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public int getMacLength() {
        return delegate.getMacLength();
    }

    @Override
    public void init(final Key key) {
        if (prevKey == key) {
            //init not needed if it is the same key
            reset(); //checks itself if reset is needed
            return;
        }
        delegate.init(key);
        prevKey = key;
        needsReset = false;
    }

    @Override
    public void update(final byte input) {
        needsReset = true;
        delegate.update(input);
    }

    @Override
    public void update(final IByteBuffer input) {
        needsReset = true;
        delegate.update(input);
    }

    @Override
    public void update(final byte[] input) {
        needsReset = true;
        delegate.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        needsReset = true;
        delegate.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        final byte[] result = delegate.doFinal();
        needsReset = false;
        return result;
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        final byte[] result = delegate.doFinal(input);
        needsReset = false;
        return result;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        delegate.doFinal(output, offset);
        needsReset = false;
        return delegate.getMacLength();
    }

    @Override
    public void reset() {
        if (needsReset) {
            delegate.reset();
        }
        needsReset = false;
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        final boolean verified = delegate.verify(input, signature);
        needsReset = true;
        return verified;
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        final boolean verified = delegate.verify(input, signature);
        needsReset = true;
        return verified;
    }

    @Override
    public void close() {
        prevKey = null;
        delegate.close();
        needsReset = false;
    }

}