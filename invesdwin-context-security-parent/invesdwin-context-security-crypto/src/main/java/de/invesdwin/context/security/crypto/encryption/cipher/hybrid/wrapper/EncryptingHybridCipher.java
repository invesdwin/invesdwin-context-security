package de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.math.Integers;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.EmptyByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class EncryptingHybridCipher implements ICipher {

    public static final int ENCRYPTEDDATAKEYLENGTH_INDEX = 0;
    public static final int ENCRYPTEDDATAKEYLENGTH_SIZE = Integer.BYTES;
    public static final int ENCRYPTEDDATAPARAMLENGTH_INDEX = ENCRYPTEDDATAKEYLENGTH_INDEX + ENCRYPTEDDATAKEYLENGTH_SIZE;
    public static final int ENCRYPTEDDATAPARAMLENGTH_SIZE = Integer.BYTES;
    public static final int ENCRYPTEDDATAKEY_INDEX = ENCRYPTEDDATAPARAMLENGTH_INDEX + ENCRYPTEDDATAPARAMLENGTH_SIZE;

    private final HybridCipher parent;
    private final IByteBuffer decryptedRandomDataKeyBuffer = ByteBuffers.allocateExpandable();
    private final IByteBuffer outputBuffer = ByteBuffers.allocateExpandable();
    private int outputBufferPosition = 0;
    private int outputBufferSize = 0;

    public EncryptingHybridCipher(final HybridCipher parent) {
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
        if (mode != CipherMode.Encrypt) {
            throw new IllegalArgumentException("Only encryption supported");
        }
        if (params != null) {
            throw new IllegalArgumentException("params not supported here: " + params);
        }
        reset();

        final IKey randomDataKey = parent.getDataEncryptionFactory().getKey().newRandomInstance();
        final int randomDataKeySize = randomDataKey.toBuffer(decryptedRandomDataKeyBuffer);
        final int encryptedDataKeySize = parent.getKeyEncryptionFactory()
                .encrypt(decryptedRandomDataKeyBuffer.sliceTo(randomDataKeySize),
                        outputBuffer.sliceFrom(ENCRYPTEDDATAKEY_INDEX), parent.getKeyCipher(), key);
        outputBuffer.putInt(ENCRYPTEDDATAKEYLENGTH_INDEX, encryptedDataKeySize);
        outputBufferSize = ENCRYPTEDDATAKEY_INDEX + encryptedDataKeySize;

        final int paramSize = parent.getDataEncryptionFactory()
                .init(mode, parent.getDataCipher(), randomDataKey, outputBuffer.sliceFrom(outputBufferSize));
        outputBuffer.putInt(ENCRYPTEDDATAPARAMLENGTH_INDEX, paramSize);
        outputBufferSize += paramSize;
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        if (outputBufferPosition != outputBufferSize) {
            //outBuffer should normally be large enough so that the additional buffering should only happen on the first call
            final int written = parent.getDataCipher().update(ByteBuffers.wrap(inBuffer), outputBuffer);
            outputBufferSize += written;
            ByteBuffers.position(inBuffer, inBuffer.capacity());
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition, outBuffer.remaining());
            outputBuffer.getBytesTo(outputBufferPosition, outBuffer, toBeOutputted);
            ByteBuffers.position(outBuffer, outBuffer.position() + toBeOutputted);
            outputBufferPosition += toBeOutputted;
            return toBeOutputted;
        } else {
            return parent.getDataCipher().update(inBuffer, outBuffer);
        }
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        if (outputBufferPosition != outputBufferSize) {
            //outBuffer should normally be large enough so that the additional buffering should only happen on the first call
            final int written = parent.getDataCipher().update(inBuffer, outputBuffer);
            outputBufferSize += written;
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition, outBuffer.capacity());
            outputBuffer.getBytesTo(outputBufferPosition, outBuffer, toBeOutputted);
            outputBufferPosition += toBeOutputted;
            return toBeOutputted;
        } else {
            return parent.getDataCipher().update(inBuffer, outBuffer);
        }
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return update(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        if (outputBufferPosition != outputBufferSize) {
            //outBuffer should normally be large enough so that the additional buffering should only happen on the first call
            final int written = parent.getDataCipher()
                    .update(ByteBuffers.wrap(input, inputOffset, inputLen), outputBuffer);
            outputBufferSize += written;
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition,
                    output.length - outputOffset);
            outputBuffer.getBytes(outputBufferPosition, output, outputOffset, toBeOutputted);
            outputBufferPosition += toBeOutputted;
            return toBeOutputted;
        } else {
            return parent.getDataCipher().update(input, inputOffset, inputLen, output, outputOffset);
        }
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        //make sure everything is written in the end (might throw bounds exception)
        int written = 0;
        if (outputBufferPosition != outputBufferSize) {
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition);
            outputBuffer.getBytesTo(outputBufferPosition, outBuffer, toBeOutputted);
            ByteBuffers.position(outBuffer, outBuffer.position() + toBeOutputted);
            outputBufferPosition += toBeOutputted;
            written += toBeOutputted;
        }

        written += parent.getDataCipher().doFinal(inBuffer, outBuffer);
        return written;
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        //make sure everything is written in the end (might throw bounds exception)
        int written = 0;
        if (outputBufferPosition != outputBufferSize) {
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition);
            outputBuffer.getBytesTo(outputBufferPosition, outBuffer, toBeOutputted);
            outputBufferPosition += toBeOutputted;
            written += toBeOutputted;
        }

        written += parent.getDataCipher().doFinal(inBuffer, outBuffer.sliceFrom(written));
        return written;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return doFinal(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        //make sure everything is written in the end (might throw bounds exception)
        int written = 0;
        if (outputBufferPosition != outputBufferSize) {
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition);
            outputBuffer.getBytes(outputBufferPosition, output, outputOffset, toBeOutputted);
            outputBufferPosition += toBeOutputted;
            written += toBeOutputted;
        }

        written += parent.getDataCipher().doFinal(input, inputOffset, inputLen, output, outputOffset + written);
        return written;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        //make sure everything is written in the end (might throw bounds exception)
        int written = 0;
        if (outputBufferPosition != outputBufferSize) {
            final int toBeOutputted = Integers.min(outputBufferSize - outputBufferPosition);
            outputBuffer.getBytes(outputBufferPosition, output, offset, toBeOutputted);
            outputBufferPosition += toBeOutputted;
            written += toBeOutputted;
        }

        written += parent.getDataCipher().doFinal(output, offset + written);
        return written;
    }

    @Override
    public byte[] doFinal() {
        //make sure everything is written in the end (might throw bounds exception)
        final int written = parent.getDataCipher()
                .doFinal(EmptyByteBuffer.INSTANCE, outputBuffer.sliceFrom(outputBufferPosition));
        outputBufferSize += written;
        final int resultSize = outputBufferSize - outputBufferPosition;
        final byte[] result = outputBuffer.asByteArrayCopy(outputBufferPosition, resultSize);
        outputBufferPosition += resultSize;
        return result;
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

    void reset() {
        outputBufferPosition = 0;
        outputBufferSize = 0;
    }

}
