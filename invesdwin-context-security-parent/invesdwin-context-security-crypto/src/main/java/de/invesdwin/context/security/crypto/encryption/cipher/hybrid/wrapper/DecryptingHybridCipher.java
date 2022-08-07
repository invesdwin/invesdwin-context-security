package de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.ByteBufferAlgorithmParameterSpec;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class DecryptingHybridCipher implements ICipher {

    private final HybridCipher parent;
    private final IByteBuffer decryptedRandomDataKeyBuffer = ByteBuffers.allocateExpandable();

    public DecryptingHybridCipher(final HybridCipher parent) {
        this.parent = parent;
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
        return parent.getAlgorithm();
    }

    @Deprecated
    @Override
    public void init(final CipherMode mode, final IKey key, final AlgorithmParameterSpec params) {
        if (mode != CipherMode.Decrypt) {
            throw new IllegalArgumentException("Only decryption supported");
        }
        final ByteBufferAlgorithmParameterSpec cParams = (ByteBufferAlgorithmParameterSpec) params;
        final IByteBuffer paramsBuffer = cParams.getBuffer();

        final int encryptedDataKeySize = paramsBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAKEYLENGTH_INDEX);
        final int encryptedDataParamSize = paramsBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAPARAMLENGTH_INDEX);
        final int encryptedDataKeyIndex = EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX;
        final int encryptedDataParamIndex = encryptedDataKeyIndex + encryptedDataKeySize;

        final int decryptedRandomDataKeySize = parent.getKeyEncryptionFactory()
                .decrypt(paramsBuffer.slice(encryptedDataKeyIndex, encryptedDataKeySize), decryptedRandomDataKeyBuffer,
                        parent.getKeyCipher(), key);
        final IKey randomDataKey = parent.getDataEncryptionFactory()
                .getKey()
                .fromBuffer(decryptedRandomDataKeyBuffer.sliceTo(decryptedRandomDataKeySize));
        parent.getDataEncryptionFactory()
                .init(mode, parent.getDataCipher(), randomDataKey,
                        paramsBuffer.slice(encryptedDataParamIndex, encryptedDataParamSize));

        cParams.setSize(encryptedDataKeyIndex + encryptedDataKeySize + encryptedDataParamSize);
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        return parent.getDataCipher().update(inBuffer, outBuffer);
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        return parent.getDataCipher().update(inBuffer, outBuffer);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return parent.getDataCipher().update(input, inputOffset, inputLen, output);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        return parent.getDataCipher().update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        return parent.getDataCipher().doFinal(inBuffer, outBuffer);
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        return parent.getDataCipher().doFinal(inBuffer, outBuffer);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return parent.getDataCipher().doFinal(input, inputOffset, inputLen, output);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        return parent.getDataCipher().doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        return parent.getDataCipher().doFinal(output, offset);
    }

    @Override
    public byte[] doFinal() {
        return parent.getDataCipher().doFinal();
    }

    @Override
    public void updateAAD(final byte input) {
        parent.getDataCipher().updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input) {
        parent.getDataCipher().updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input, final int inputOffset, final int inputLen) {
        parent.getDataCipher().updateAAD(input, inputOffset, inputLen);
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer input) {
        parent.getDataCipher().updateAAD(input);
    }

    @Override
    public void updateAAD(final IByteBuffer input) {
        parent.getDataCipher().updateAAD(input);
    }

    @Override
    public void close() {
    }

}
