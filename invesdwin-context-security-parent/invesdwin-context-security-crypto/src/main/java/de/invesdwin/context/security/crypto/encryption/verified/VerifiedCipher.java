package de.invesdwin.context.security.crypto.encryption.verified;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * WARNING: VerifiedCipher update calls always return a written length of 0 despite writing to the given output (same as
 * com.sun.crypto.provider.GaloisCounterMode.GCMDecrypt.doUpdate(byte[], int, int, byte[], int)). This makes using the
 * cipher directly unsuitable. It is only useful inside VerifiedEncryptionFactory (with its own drawbacks).
 */
@NotThreadSafe
public class VerifiedCipher implements ICipher {

    private final ICipher unverifiedCipher;
    private final IHash hash;
    private final EncryptingVerifiedCipher encryptingDelegate;
    private final DecryptingVerifiedCipher decryptingDelegate;
    private final IVerificationFactory authenticationFactory;
    private ICipher delegate;

    public VerifiedCipher(final ICipher unverifiedCipher, final IVerificationFactory verificationFactory) {
        this.unverifiedCipher = unverifiedCipher;
        this.hash = verificationFactory.getAlgorithm().newHash();
        this.encryptingDelegate = new EncryptingVerifiedCipher(unverifiedCipher, verificationFactory, hash);
        this.decryptingDelegate = new DecryptingVerifiedCipher(unverifiedCipher, verificationFactory, hash);
        this.authenticationFactory = verificationFactory;
    }

    public ICipher getUnverifiedCipher() {
        return unverifiedCipher;
    }

    public IHash getHash() {
        return hash;
    }

    public IVerificationFactory getAuthenticationFactory() {
        return authenticationFactory;
    }

    @Override
    public int getBlockSize() {
        return unverifiedCipher.getBlockSize();
    }

    @Override
    public int getHashSize() {
        return unverifiedCipher.getHashSize() + hash.getHashSize();
    }

    @Override
    public String getAlgorithm() {
        return unverifiedCipher.getAlgorithm() + "With" + hash.getAlgorithm();
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
        hash.update(input, inputOffset, inputLen);
        written += hash.doFinal(output, written);
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
        unverifiedCipher.close();
        hash.close();
        encryptingDelegate.reset();
        decryptingDelegate.reset();
    }

}
