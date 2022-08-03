package de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class HybridCipher implements ICipher {

    private final IEncryptionFactory keyEncryptionFactory;
    private final IEncryptionFactory dataEncryptionFactory;
    private ICipher keyCipher;
    private ICipher dataCipher;
    private final EncryptingHybridCipher encryptingDelegate;
    private final DecryptingHybridCipher decryptingDelegate;
    private ICipher delegate;

    public HybridCipher(final IEncryptionFactory keyEncryptionFactory, final IEncryptionFactory dataEncryptionFactory) {
        this(keyEncryptionFactory, dataEncryptionFactory, keyEncryptionFactory.getAlgorithm().newCipher(),
                dataEncryptionFactory.getAlgorithm().newCipher());
    }

    public HybridCipher(final IEncryptionFactory firstEncryptionFactory,
            final IEncryptionFactory secondEncryptionFactory, final ICipher keyCipher, final ICipher dataCipher) {
        this.keyEncryptionFactory = firstEncryptionFactory;
        this.dataEncryptionFactory = secondEncryptionFactory;
        this.keyCipher = keyCipher;
        this.dataCipher = dataCipher;
        this.encryptingDelegate = new EncryptingHybridCipher(this);
        this.decryptingDelegate = new DecryptingHybridCipher(this);
    }

    public ICipher getKeyCipher() {
        return keyCipher;
    }

    //package private for the pool
    void setKeyCipher(final ICipher firstCipher) {
        this.keyCipher = firstCipher;
    }

    public ICipher getDataCipher() {
        return dataCipher;
    }

    //package private for the pool
    void setDataCipher(final ICipher secondCipher) {
        this.dataCipher = secondCipher;
    }

    @Override
    public int getBlockSize() {
        return keyCipher.getBlockSize();
    }

    @Override
    public int getHashSize() {
        return dataCipher.getHashSize();
    }

    @Override
    public String getAlgorithm() {
        return keyCipher.getAlgorithm() + "With" + dataCipher.getAlgorithm();
    }

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
        if (keyCipher != null) {
            keyCipher.close();
            keyCipher = null;
        }
        if (dataCipher != null) {
            dataCipher.close();
            dataCipher = null;
        }
        encryptingDelegate.reset();
        decryptingDelegate.reset();
    }

}
