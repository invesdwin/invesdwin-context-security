package de.invesdwin.context.security.crypto.encryption.cipher.wrapper.authenticated;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class AuthenticatedCipher implements ICipher {

    private final ICipher unauthenticatedCipher;
    private final IMac mac;
    private final EncryptingAuthenticatedCipher encryptingDelegate;
    private final DecryptingAuthenticatedCipher decryptingDelegate;
    private final IAuthenticationFactory authenticationFactory;
    private ICipher delegate;

    public AuthenticatedCipher(final ICipher unauthenticatedCipher,
            final IAuthenticationFactory authenticationFactory) {
        this.unauthenticatedCipher = unauthenticatedCipher;
        this.mac = authenticationFactory.getAlgorithm().newMac();
        this.encryptingDelegate = new EncryptingAuthenticatedCipher(unauthenticatedCipher, authenticationFactory, mac);
        this.decryptingDelegate = new DecryptingAuthenticatedCipher(unauthenticatedCipher, authenticationFactory, mac);
        this.authenticationFactory = authenticationFactory;
    }

    public ICipher getUnauthenticatedCipher() {
        return unauthenticatedCipher;
    }

    public IMac getMac() {
        return mac;
    }

    public IAuthenticationFactory getAuthenticationFactory() {
        return authenticationFactory;
    }

    @Override
    public int getBlockSize() {
        return unauthenticatedCipher.getBlockSize();
    }

    @Override
    public int getSignatureSize() {
        return unauthenticatedCipher.getSignatureSize() + mac.getMacLength();
    }

    @Override
    public String getAlgorithm() {
        return unauthenticatedCipher.getAlgorithm() + "With" + mac.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        switch (mode) {
        case Cipher.ENCRYPT_MODE:
            delegate = encryptingDelegate;
            break;
        case Cipher.DECRYPT_MODE:
            delegate = decryptingDelegate;
            break;
        default:
            throw UnknownArgumentException.newInstance(int.class, mode);
        }
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
        int written = delegate.doFinal(input, inputOffset, inputLen, output);
        mac.update(input, inputOffset, inputLen);
        written += mac.doFinal(output, written);
        return written;
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
        unauthenticatedCipher.close();
        mac.close();
        encryptingDelegate.reset();
        decryptingDelegate.reset();
    }

}
