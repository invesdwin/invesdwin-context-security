package de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.math.Integers;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class DecryptingHybridCipher implements ICipher {

    private final HybridCipher parent;

    private final byte[] oneByteBuf = new byte[1];
    private final IByteBuffer decryptedRandomDataKeyBuffer = ByteBuffers.allocateExpandable();
    private final IByteBuffer inputBuffer = ByteBuffers.allocateExpandable();
    private int inputBufferPosition = 0;
    private int inputBufferSize = 0;
    private int expectedInputBufferSize = -1;
    private IKey prevKey;
    private boolean initialized = false;

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
        if (params != null) {
            throw new IllegalArgumentException("params not supported here: " + params);
        }
        reset();
        this.prevKey = key;
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int read = maybeInit(inBuffer);
        ByteBuffers.position(inBuffer, inBuffer.position() + read);
        return parent.getDataCipher().update(inBuffer, outBuffer);
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int read = maybeInit(inBuffer);
        return parent.getDataCipher().update(inBuffer.sliceFrom(read), outBuffer);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return update(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        final int read = maybeInit(input, inputOffset, inputLen);
        return parent.getDataCipher().update(input, inputOffset + read, inputLen - read, output, outputOffset);
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        final int read = maybeInit(inBuffer);
        ByteBuffers.position(inBuffer, inBuffer.position() + read);
        assertInitialized();
        return parent.getDataCipher().doFinal(inBuffer, outBuffer);
    }

    private void assertInitialized() {
        if (!initialized) {
            throw new IllegalStateException("Not initialized yet");
        }
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final int read = maybeInit(inBuffer);
        assertInitialized();
        return parent.getDataCipher().doFinal(inBuffer.sliceFrom(read), outBuffer);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return doFinal(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        final int read = maybeInit(input, inputOffset, inputLen);
        assertInitialized();
        return parent.getDataCipher().doFinal(input, inputOffset + read, inputLen - read, output, outputOffset);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        assertInitialized();
        return parent.getDataCipher().doFinal(output, offset);
    }

    @Override
    public byte[] doFinal() {
        assertInitialized();
        return parent.getDataCipher().doFinal();
    }

    @Override
    public void updateAAD(final byte input) {
        oneByteBuf[0] = input;
        updateAAD(oneByteBuf, 0, oneByteBuf.length);
    }

    @Override
    public void updateAAD(final byte[] input) {
        updateAAD(input, 0, input.length);
    }

    @Override
    public void updateAAD(final byte[] input, final int inputOffset, final int inputLen) {
        final int read = maybeInit(input, inputOffset, inputLen);
        parent.getDataCipher().updateAAD(input, inputOffset + read, inputLen - read);
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer input) {
        final int read = maybeInit(input);
        ByteBuffers.position(input, input.position() + read);
        parent.getDataCipher().updateAAD(input);
    }

    @Override
    public void updateAAD(final IByteBuffer input) {
        final int read = maybeInit(input);
        parent.getDataCipher().updateAAD(input.sliceFrom(read));
    }

    private int maybeInit(final java.nio.ByteBuffer inBuffer) {
        if (initialized) {
            return 0;
        }
        int read = 0;
        if (inputBufferSize < EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX) {
            final int toBeWritten = Integers.min(EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX - inputBufferPosition,
                    inBuffer.remaining());
            inputBuffer.putBytesTo(inputBufferPosition, inBuffer, toBeWritten);
            inputBufferSize += toBeWritten;
            read += toBeWritten;
            ByteBuffers.position(inBuffer, inBuffer.position() + toBeWritten);
            if (inputBufferSize == EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX) {
                expectedInputBufferSize = inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAKEYLENGTH_INDEX)
                        + inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAPARAMLENGTH_INDEX);
            }
        }
        if (inputBufferSize < expectedInputBufferSize) {
            final int toBeWritten = Integers.min(expectedInputBufferSize - inputBufferPosition, inBuffer.remaining());
            inputBuffer.putBytesTo(inputBufferPosition, inBuffer, toBeWritten);
            inputBufferSize += toBeWritten;
            read += toBeWritten;
            ByteBuffers.position(inBuffer, inBuffer.position() + toBeWritten);
            if (inputBufferSize == expectedInputBufferSize) {
                initialize();
            }
        }
        return read;
    }

    private int maybeInit(final IByteBuffer inBuffer) {
        if (initialized) {
            return 0;
        }
        int read = 0;
        if (inputBufferSize < EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX) {
            final int toBeWritten = Integers.min(EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX - inputBufferPosition,
                    inBuffer.capacity());
            inputBuffer.putBytesTo(inputBufferPosition, inBuffer, toBeWritten);
            inputBufferSize += toBeWritten;
            read += toBeWritten;
            if (inputBufferSize == EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX) {
                expectedInputBufferSize = inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAKEYLENGTH_INDEX)
                        + inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAPARAMLENGTH_INDEX);
            }
        }
        if (inputBufferSize < expectedInputBufferSize) {
            final int toBeWritten = Integers.min(expectedInputBufferSize - inputBufferPosition,
                    inBuffer.remaining(read));
            inputBuffer.putBytesTo(inputBufferPosition, inBuffer, toBeWritten);
            inputBufferSize += toBeWritten;
            read += toBeWritten;
            if (inputBufferSize == expectedInputBufferSize) {
                initialize();
            }
        }
        return read;
    }

    private int maybeInit(final byte[] input, final int inputOffset, final int inputLen) {
        if (initialized) {
            return 0;
        }
        int read = 0;
        if (inputBufferSize < EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX) {
            final int toBeWritten = Integers.min(EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX - inputBufferPosition,
                    inputLen);
            inputBuffer.putBytes(inputBufferPosition, input, inputOffset, toBeWritten);
            inputBufferSize += toBeWritten;
            read += toBeWritten;
            if (inputBufferSize == EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX) {
                expectedInputBufferSize = inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAKEYLENGTH_INDEX)
                        + inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAPARAMLENGTH_INDEX);
            }
        }
        if (inputBufferSize < expectedInputBufferSize) {
            final int toBeWritten = Integers.min(expectedInputBufferSize - inputBufferPosition, inputLen - read);
            inputBuffer.putBytes(inputBufferPosition, input, inputOffset + read, toBeWritten);
            inputBufferSize += toBeWritten;
            read += toBeWritten;
            if (inputBufferSize == expectedInputBufferSize) {
                initialize();
            }
        }
        return read;
    }

    private void initialize() {
        final int encryptedDataKeySize = inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAKEYLENGTH_INDEX);
        final int encryptedDataParamSize = inputBuffer.getInt(EncryptingHybridCipher.ENCRYPTEDDATAPARAMLENGTH_INDEX);
        final int encryptedDataKeyIndex = EncryptingHybridCipher.ENCRYPTEDDATAKEY_INDEX;
        final int encryptedDataParamIndex = encryptedDataKeyIndex + encryptedDataKeySize;

        final int decryptedRandomDataKeySize = parent.getKeyEncryptionFactory()
                .decrypt(inputBuffer.slice(encryptedDataKeyIndex, encryptedDataKeySize), decryptedRandomDataKeyBuffer,
                        parent.getKeyCipher(), prevKey);
        final IKey randomDataKey = parent.getDataEncryptionFactory()
                .getKey()
                .fromBuffer(decryptedRandomDataKeyBuffer.sliceTo(decryptedRandomDataKeySize));
        parent.getDataEncryptionFactory()
                .init(CipherMode.Decrypt, parent.getDataCipher(), randomDataKey,
                        inputBuffer.slice(encryptedDataParamIndex, encryptedDataParamSize));

        initialized = true;
    }

    @Override
    public void close() {
    }

    void reset() {
        initialized = false;
        inputBufferPosition = 0;
        inputBufferSize = 0;
        expectedInputBufferSize = -1;
        prevKey = null;
    }

}
