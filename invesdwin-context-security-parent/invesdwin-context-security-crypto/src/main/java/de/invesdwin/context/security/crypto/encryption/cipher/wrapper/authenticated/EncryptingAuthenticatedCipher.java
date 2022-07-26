package de.invesdwin.context.security.crypto.encryption.cipher.wrapper.authenticated;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class EncryptingAuthenticatedCipher implements ICipher {

    private final ICipher delegate;
    private final IAuthenticationFactory authenticationFactory;
    private final IMac mac;

    public EncryptingAuthenticatedCipher(final ICipher getUnauthenticatedCipher,
            final IAuthenticationFactory authenticationFactory, final IMac mac) {
        this.delegate = getUnauthenticatedCipher;
        this.authenticationFactory = authenticationFactory;
        this.mac = mac;
    }

    public ICipher getUnauthenticatedCipher() {
        return delegate;
    }

    public IMac getMac() {
        return mac;
    }

    public IAuthenticationFactory getAuthenticationFactory() {
        return authenticationFactory;
    }

    @Override
    public int getBlockSize() {
        return delegate.getBlockSize();
    }

    @Override
    public int getSignatureSize() {
        return delegate.getSignatureSize() + mac.getMacLength();
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm() + "With" + mac.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        if (mode != Cipher.ENCRYPT_MODE) {
            throw new IllegalArgumentException("Only encryption supported");
        }
        delegate.init(mode, key, params);
        authenticationFactory.init(mac);
        reset();
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = outBuffer.position();
        final int length = delegate.update(inBuffer, outBuffer);
        mac.update(ByteBuffers.slice(outBuffer, positionBefore, length));
        return length;
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int length = delegate.update(inBuffer, outBuffer);
        mac.update(outBuffer.sliceTo(length));
        return length;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        final int length = delegate.update(input, inputOffset, inputLen, output);
        mac.update(output, 0, length);
        return length;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        final int length = delegate.update(input, inputOffset, inputLen, output, outputOffset);
        mac.update(output, outputOffset, length);
        return length;
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = outBuffer.position();
        final int written = delegate.doFinal(inBuffer, outBuffer);
        mac.update(ByteBuffers.slice(outBuffer, positionBefore, written));
        final byte[] signature = mac.doFinal();
        outBuffer.put(signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int written = delegate.doFinal(inBuffer, outBuffer);
        mac.update(outBuffer.slice(0, written));
        final byte[] signature = mac.doFinal();
        outBuffer.putBytes(written, signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        int written = delegate.doFinal(input, inputOffset, inputLen, output);
        mac.update(output, 0, written);
        written += mac.doFinal(output, written);
        return written;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        int written = delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
        mac.update(output, outputOffset, written);
        written += mac.doFinal(output, outputOffset + written);
        return written;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        int written = delegate.doFinal(output, offset);
        mac.update(output, offset, written);
        written += mac.doFinal(output, offset + written);
        return written;
    }

    @Override
    public byte[] doFinal() {
        final byte[] payload = delegate.doFinal();
        mac.update(payload);
        final byte[] signature = mac.doFinal();
        return Bytes.concat(payload, signature);
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
        delegate.close();
        mac.close();
    }

    void reset() {
        //noop
    }

}
