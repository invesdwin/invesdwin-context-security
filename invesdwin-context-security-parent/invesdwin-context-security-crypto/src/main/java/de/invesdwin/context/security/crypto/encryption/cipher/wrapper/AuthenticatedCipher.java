package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class AuthenticatedCipher implements ICipher {

    private final ICipher delegate;
    private final IAuthenticationFactory authenticationFactory;
    private final IMac mac;

    public AuthenticatedCipher(final ICipher delegate, final IAuthenticationFactory authenticationFactory) {
        this.delegate = delegate;
        this.authenticationFactory = authenticationFactory;
        this.mac = authenticationFactory.getAlgorithm().newMac();
    }

    public ICipher getDelegate() {
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
        delegate.init(mode, key, params);
        authenticationFactory.init(mac);
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = inBuffer.position();
        final int length = delegate.update(inBuffer, outBuffer);
        ByteBuffers.position(inBuffer, positionBefore);
        mac.update(inBuffer);
        return length;
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int length = delegate.update(inBuffer, outBuffer);
        mac.update(inBuffer);
        return length;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        final int length = delegate.update(input, inputOffset, inputLen, output);
        mac.update(input, inputOffset, inputLen);
        return length;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        final int length = delegate.update(input, inputOffset, inputLen, output, outputOffset);
        mac.update(input, inputOffset, inputLen);
        return length;
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = inBuffer.position();
        final int written = delegate.doFinal(inBuffer, outBuffer);
        ByteBuffers.position(inBuffer, positionBefore);
        mac.update(inBuffer);
        final byte[] signature = mac.doFinal();
        outBuffer.put(signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        return ICipher.super.doFinal(inBuffer, outBuffer);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        int written = delegate.doFinal(input, inputOffset, inputLen, output);
        mac.update(input, inputOffset, inputLen);
        written += mac.doFinal(output, written);
        return written;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        int written = delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
        mac.update(input, inputOffset, inputLen);
        written += mac.doFinal(output, outputOffset + written);
        return written;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        int written = delegate.doFinal(output, offset);
        written += mac.doFinal(output, offset + written);
        return written;
    }

    @Override
    public byte[] doFinal() {
        final byte[] payload = delegate.doFinal();
        final byte[] signature = mac.doFinal();
        return Bytes.concat(payload, signature);
    }

    @Override
    public void updateAAD(final byte aad) {
        delegate.updateAAD(aad);
        mac.update(aad);
    }

    @Override
    public void updateAAD(final byte[] aad) {
        delegate.updateAAD(aad);
        mac.update(aad);
    }

    @Override
    public void updateAAD(final byte[] aad, final int inputOffset, final int inputLen) {
        delegate.updateAAD(aad, inputOffset, inputLen);
        mac.update(aad, inputOffset, inputLen);
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer aad) {
        delegate.updateAAD(aad);
        mac.update(aad);
    }

    @Override
    public void updateAAD(final IByteBuffer aad) {
        delegate.updateAAD(aad);
        mac.update(aad);
    }

    @Override
    public void close() {
        delegate.close();
        mac.close();
    }

}
