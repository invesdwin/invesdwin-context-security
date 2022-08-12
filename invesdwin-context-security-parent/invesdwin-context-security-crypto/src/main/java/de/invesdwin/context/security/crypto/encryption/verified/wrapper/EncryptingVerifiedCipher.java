package de.invesdwin.context.security.crypto.encryption.verified.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.ByteBufferAlgorithmParameterSpec;
import de.invesdwin.context.security.crypto.encryption.verified.VerifiedCipherKey;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class EncryptingVerifiedCipher implements ICipher {

    private final VerifiedCipher parent;

    public EncryptingVerifiedCipher(final VerifiedCipher parent) {
        this.parent = parent;
    }

    private ICipher getDelegate() {
        return parent.getUnverifiedCipher();
    }

    private IHash getHash() {
        return parent.getHash();
    }

    @Override
    public int getBlockSize() {
        return parent.getBlockSize();
    }

    @Override
    public int getHashSize() {
        return parent.getHashSize();
    }

    @Override
    public String getAlgorithm() {
        return getDelegate().getAlgorithm() + "With" + getHash().getAlgorithm();
    }

    @Deprecated
    @Override
    public void init(final CipherMode mode, final IKey key, final AlgorithmParameterSpec params) {
        if (mode != CipherMode.Encrypt) {
            throw new IllegalArgumentException("Only encryption supported");
        }
        final VerifiedCipherKey cKey = (VerifiedCipherKey) key;
        if (params instanceof ByteBufferAlgorithmParameterSpec) {
            final ByteBufferAlgorithmParameterSpec cParams = (ByteBufferAlgorithmParameterSpec) params;
            final int paramsSize = parent.getEncryptionFactory()
                    .init(mode, parent.getUnverifiedCipher(), cKey.getEncryptionKey(), cParams.getBuffer());
            cParams.setSize(paramsSize);
        } else {
            getDelegate().init(mode, cKey.getEncryptionKey(), params);
        }
        getHash().init(mode.getHashMode(), cKey.getVerificationKey());
        reset();
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = outBuffer.position();
        final int length = getDelegate().update(inBuffer, outBuffer);
        getHash().update(ByteBuffers.slice(outBuffer, positionBefore, length));
        /*
         * we need to force StreamingCipherOutputStream to call doFinal in the same intervals as
         * StreamingCipherInputStream, thus use the settings of DecryptingVerifiedCipher. Smaller chunks will make sure
         * that the buffering in DecryptingVerifiedCipher does not grow too large, though it will cause more network
         * overhead.
         */
        return 0;
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int length = getDelegate().update(inBuffer, outBuffer);
        getHash().update(outBuffer.sliceTo(length));
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        final int length = getDelegate().update(input, inputOffset, inputLen, output);
        getHash().update(output, 0, length);
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        final int length = getDelegate().update(input, inputOffset, inputLen, output, outputOffset);
        getHash().update(output, outputOffset, length);
        return 0;
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int positionBefore = outBuffer.position();
        final int written = getDelegate().doFinal(inBuffer, outBuffer);
        getHash().update(ByteBuffers.slice(outBuffer, positionBefore, written));
        final byte[] signature = getHash().doFinal();
        outBuffer.put(signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int written = getDelegate().doFinal(inBuffer, outBuffer);
        getHash().update(outBuffer.slice(0, written));
        final byte[] signature = getHash().doFinal();
        outBuffer.putBytes(written, signature);
        return written + signature.length;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        int written = getDelegate().doFinal(input, inputOffset, inputLen, output);
        getHash().update(output, 0, written);
        written += getHash().doFinal(output, written);
        return written;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        int written = getDelegate().doFinal(input, inputOffset, inputLen, output, outputOffset);
        getHash().update(output, outputOffset, written);
        written += getHash().doFinal(output, outputOffset + written);
        return written;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        int written = getDelegate().doFinal(output, offset);
        getHash().update(output, offset, written);
        written += getHash().doFinal(output, offset + written);
        return written;
    }

    @Override
    public byte[] doFinal() {
        final byte[] payload = getDelegate().doFinal();
        getHash().update(payload);
        final byte[] signature = getHash().doFinal();
        return Bytes.concat(payload, signature);
    }

    @Override
    public void updateAAD(final byte input) {
        getDelegate().updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input) {
        getDelegate().updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input, final int inputOffset, final int inputLen) {
        getDelegate().updateAAD(input, inputOffset, inputLen);
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer input) {
        getDelegate().updateAAD(input);
    }

    @Override
    public void updateAAD(final IByteBuffer input) {
        getDelegate().updateAAD(input);
    }

    @Override
    public void close() {
    }

    void reset() {
        //noop
    }

}
