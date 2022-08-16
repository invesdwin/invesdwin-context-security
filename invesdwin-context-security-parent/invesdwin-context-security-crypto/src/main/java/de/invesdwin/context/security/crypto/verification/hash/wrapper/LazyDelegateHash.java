package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class LazyDelegateHash implements IHash {

    private final IHash delegate;
    private boolean needsReset;
    /**
     * Not storing identity here because this might cause collisions if the object is already released. Instead using
     * close() to clear up the reference.
     */
    private IKey prevKey;
    private HashMode prevMode;

    public LazyDelegateHash(final IHash delegate) {
        this.delegate = delegate;
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm();
    }

    @Override
    public boolean isDynamicHashSize() {
        return delegate.isDynamicHashSize();
    }

    @Override
    public int getHashSize() {
        return delegate.getHashSize();
    }

    @Override
    public void init(final HashMode mode, final IKey key) {
        if (prevKey == key && mode == prevMode) {
            //init not needed if it is the same key
            reset(); //checks itself if reset is needed
            return;
        }
        delegate.init(mode, key);
        prevKey = key;
        prevMode = mode;
        needsReset = false;
    }

    @Override
    public void update(final byte input) {
        needsReset = true;
        delegate.update(input);
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
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
        final int written = delegate.doFinal(output, offset);
        needsReset = false;
        return written;
    }

    @Override
    public void reset() {
        if (needsReset) {
            delegate.reset();
            needsReset = false;
        }
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        final boolean verified = delegate.verify(input, signature);
        needsReset = false;
        return verified;
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        final boolean verified = delegate.verify(input, signature);
        needsReset = false;
        return verified;
    }

    @Override
    public void close() {
        prevKey = null;
        prevMode = null;
        delegate.close();
        needsReset = false;
    }

}
