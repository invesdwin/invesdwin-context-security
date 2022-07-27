package de.invesdwin.context.security.crypto.encryption.verified;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class EncryptingVerifiedCipher implements ICipher {

    private final ICipher delegate;
    private final IVerificationFactory verificationFactory;
    private final IHash hash;

    public EncryptingVerifiedCipher(final ICipher unverifiedCipher, final IVerificationFactory authenticationFactory,
            final IHash mac) {
        this.delegate = unverifiedCipher;
        this.verificationFactory = authenticationFactory;
        this.hash = mac;
    }

    public ICipher getUnverifiedCipher() {
        return delegate;
    }

    public IHash getHash() {
        return hash;
    }

    public IVerificationFactory getVerificationFactory() {
        return verificationFactory;
    }

    @Override
    public int getBlockSize() {
        return delegate.getBlockSize();
    }

    @Override
    public int getHashSize() {
        return delegate.getHashSize() + hash.getHashSize();
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm() + "With" + hash.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        if (mode != Cipher.ENCRYPT_MODE) {
            throw new IllegalArgumentException("Only encryption supported");
        }
        delegate.init(mode, key, params);
        verificationFactory.init(hash);
        reset();
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = outBuffer.position();
        final int length = delegate.update(inBuffer, outBuffer);
        hash.update(ByteBuffers.slice(outBuffer, positionBefore, length));
        /*
         * we need to force StreamingCipherOutputBuffer to call doFinal in the same intervals as
         * StreamingCipherInputBuffer, thus use the settings of DecryptingVerifiedCipher. Smaller chunks will make sure
         * that the buffering in DecryptingVerifiedCipher does not grow too large, though it will cause more network
         * overhead.
         */
        return 0;
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int length = delegate.update(inBuffer, outBuffer);
        hash.update(outBuffer.sliceTo(length));
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        final int length = delegate.update(input, inputOffset, inputLen, output);
        hash.update(output, 0, length);
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        final int length = delegate.update(input, inputOffset, inputLen, output, outputOffset);
        hash.update(output, outputOffset, length);
        return 0;
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = outBuffer.position();
        final int written = delegate.doFinal(inBuffer, outBuffer);
        hash.update(ByteBuffers.slice(outBuffer, positionBefore, written));
        final byte[] signature = hash.doFinal();
        outBuffer.put(signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int written = delegate.doFinal(inBuffer, outBuffer);
        hash.update(outBuffer.slice(0, written));
        final byte[] signature = hash.doFinal();
        outBuffer.putBytes(written, signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        int written = delegate.doFinal(input, inputOffset, inputLen, output);
        hash.update(output, 0, written);
        written += hash.doFinal(output, written);
        return written;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        int written = delegate.doFinal(input, inputOffset, inputLen, output, outputOffset);
        hash.update(output, outputOffset, written);
        written += hash.doFinal(output, outputOffset + written);
        return written;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        int written = delegate.doFinal(output, offset);
        hash.update(output, offset, written);
        written += hash.doFinal(output, offset + written);
        return written;
    }

    @Override
    public byte[] doFinal() {
        final byte[] payload = delegate.doFinal();
        hash.update(payload);
        final byte[] signature = hash.doFinal();
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
        hash.close();
    }

    void reset() {
        //noop
    }

}
