package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.ICipherFactory;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Does not reuse cipher instances (e.g. GCM will refuse to encrypt twice in a row with the same IV)
 * 
 * This will cause a significant drop in performance because cipher instances can not be reused.
 */
@NotThreadSafe
public class RefreshingDelegateCipher implements ICipher {

    private final ICipherAlgorithm algorithm;
    private final ICipherFactory factory;
    private ICipher delegate;

    public RefreshingDelegateCipher(final ICipherAlgorithm algorithm, final ICipherFactory factory) {
        this.algorithm = algorithm;
        this.factory = factory;
    }

    @Override
    public int getBlockSize() {
        if (delegate == null) {
            throw new IllegalStateException("initialize first");
        }
        return delegate.getBlockSize();
    }

    @Override
    public int getHashSize() {
        return delegate.getHashSize();
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        if (delegate != null) {
            delegate.close();
        }
        delegate = factory.newCipher();
        delegate.init(mode, key, params);
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        return delegate.update(inBuffer, outBuffer);
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        return delegate.update(inBuffer, outBuffer);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return delegate.update(input, inputOffset, inputLen, output);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        return delegate.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        return delegate.doFinal(inBuffer, outBuffer);
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        return delegate.doFinal(inBuffer, outBuffer);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return delegate.doFinal(input, inputOffset, inputLen, output);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        return delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        return delegate.doFinal(output, offset);
    }

    @Override
    public byte[] doFinal() {
        return delegate.doFinal();
    }

    @Override
    public void updateAAD(final byte input) {
        delegate.updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input) {
        delegate.updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input, final int inputOffset, final int inputLen) {
        delegate.updateAAD(input, inputOffset, inputLen);
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer input) {
        delegate.updateAAD(input);
    }

    @Override
    public void updateAAD(final IByteBuffer input) {
        delegate.updateAAD(input);
    }

    @Override
    public void close() {
        if (delegate != null) {
            delegate.close();
            delegate = null;
        }
    }

}
