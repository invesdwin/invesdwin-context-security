package de.invesdwin.context.security.crypto.encryption.verified.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.key.IKey;
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

    private ICipher unverifiedCipher;
    private IHash hash;
    private final EncryptingVerifiedCipher encryptingDelegate;
    private final DecryptingVerifiedCipher decryptingDelegate;
    private ICipher delegate;

    public VerifiedCipher(final ICipher unverifiedCipher, final IHash hash) {
        this.unverifiedCipher = unverifiedCipher;
        this.hash = hash;
        this.encryptingDelegate = new EncryptingVerifiedCipher(this);
        this.decryptingDelegate = new DecryptingVerifiedCipher(this);
    }

    public ICipher getUnverifiedCipher() {
        return unverifiedCipher;
    }

    public void setUnverifiedCipher(final ICipher unverifiedCipher) {
        this.unverifiedCipher = unverifiedCipher;
    }

    public IHash getHash() {
        return hash;
    }

    public void setHash(final IHash hash) {
        this.hash = hash;
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

    @Deprecated
    @Override
    public void init(final CipherMode mode, final IKey key, final AlgorithmParameterSpec params) {
        switch (mode) {
        case Encrypt:
            delegate = encryptingDelegate;
            break;
        case Decrypt:
            delegate = decryptingDelegate;
            break;
        default:
            throw UnknownArgumentException.newInstance(CipherMode.class, mode);
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
        if (unverifiedCipher != null) {
            unverifiedCipher.close();
            unverifiedCipher = null;
        }
        if (hash != null) {
            hash.close();
            hash = null;
        }
        encryptingDelegate.reset();
        decryptingDelegate.reset();
    }

}
