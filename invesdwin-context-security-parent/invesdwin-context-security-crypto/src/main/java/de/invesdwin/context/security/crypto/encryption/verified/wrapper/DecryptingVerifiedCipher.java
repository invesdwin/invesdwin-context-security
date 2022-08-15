package de.invesdwin.context.security.crypto.encryption.verified.wrapper;

import java.security.spec.AlgorithmParameterSpec;
import java.util.NoSuchElementException;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.ByteBufferAlgorithmParameterSpec;
import de.invesdwin.context.security.crypto.encryption.verified.VerifiedCipherKey;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.collections.iterable.buffer.BufferingIterator;
import de.invesdwin.util.collections.iterable.buffer.IBufferingIterator;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.math.Integers;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.EmptyByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class DecryptingVerifiedCipher implements ICipher {

    private final VerifiedCipher parent;

    /**
     * We have to verify everything before starting with the decryption:
     * https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html
     */
    private final IByteBuffer inputBuffer = ByteBuffers.allocateExpandable();
    private final IBufferingIterator<Runnable> inputBufferTasks = new BufferingIterator<>();
    private int inputBufferPosition = 0;

    private final IByteBuffer outputBuffer = ByteBuffers.allocateExpandable();
    private int outputBufferPosition = 0;

    public DecryptingVerifiedCipher(final VerifiedCipher parent) {
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

    /**
     * This will be called by encryptionFactory.
     */
    @Deprecated
    @Override
    public void init(final CipherMode mode, final IKey key, final AlgorithmParameterSpec params) {
        if (mode != CipherMode.Decrypt) {
            throw new IllegalArgumentException("Only decryption supported");
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
        update(inBuffer);
        return 0;
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        update(inBuffer);
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return update(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        update(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        if (inputBufferPosition == 0) {
            //skip buffer
            final int written = doFinal(ByteBuffers.wrap(inBuffer), ByteBuffers.wrap(outBuffer));
            ByteBuffers.position(inBuffer, inBuffer.limit());
            ByteBuffers.position(outBuffer, outBuffer.position() + written);
            return written;
        } else {
            update(inBuffer);
            final IByteBuffer decrypted = verifyAndDrainOutput();
            final int length = decrypted.capacity();
            decrypted.getBytesTo(0, outBuffer, length);
            ByteBuffers.position(outBuffer, outBuffer.position() + length);
            return length;
        }
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        if (inputBufferPosition == 0) {
            //skip buffer
            final IByteBuffer inBufferSliced = getHash().verifyAndSlice(inBuffer);
            return getDelegate().doFinal(inBufferSliced, outBuffer);
        } else {
            update(inBuffer);
            final IByteBuffer decrypted = verifyAndDrainOutput();
            final int length = decrypted.capacity();
            decrypted.getBytesTo(0, outBuffer, length);
            return length;
        }
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return doFinal(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        if (inputBufferPosition == 0) {
            return doFinal(ByteBuffers.wrap(input, inputOffset, inputLen), ByteBuffers.wrapFrom(output, outputOffset));
        } else {
            update(input, inputOffset, inputLen);
            return doFinal(output, outputOffset);
        }
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        if (inputBufferPosition == 0) {
            //nothing to verify
            return 0;
        } else {
            final IByteBuffer decrypted = verifyAndDrainOutput();
            final int outputLength = output.length - offset;
            if (outputLength > decrypted.capacity()) {
                throw new IllegalArgumentException(
                        "Insufficient output length [" + outputLength + "] for required: " + outputBufferPosition);
            }
            decrypted.getBytesFrom(0, output, offset);
            return outputLength;
        }
    }

    @Override
    public byte[] doFinal() {
        if (inputBufferPosition == 0) {
            //nothing to verify
            return Bytes.EMPTY_ARRAY;
        } else {
            final IByteBuffer decrypted = verifyAndDrainOutput();
            return decrypted.asByteArrayCopy();
        }
    }

    private IByteBuffer verifyAndDrainOutput() {
        getHash().verifyThrow(inputBuffer.sliceTo(inputBufferPosition));
        try {
            while (true) {
                final Runnable next = inputBufferTasks.next();
                next.run();
            }
        } catch (final NoSuchElementException e) {
            //end reached
        }
        final int written = getDelegate().doFinal(EmptyByteBuffer.INSTANCE,
                outputBuffer.sliceFrom(outputBufferPosition));
        outputBufferPosition += written;
        return outputBuffer.sliceTo(outputBufferPosition);
    }

    @Override
    public void updateAAD(final byte input) {
        final int position = inputBufferPosition;
        final int length = Byte.BYTES;
        inputBuffer.putByte(position, input);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainAAD(position, length));
    }

    @Override
    public void updateAAD(final byte[] input) {
        final int position = inputBufferPosition;
        final int length = input.length;
        inputBuffer.putBytes(position, input);
        inputBufferTasks.add(() -> drainAAD(position, length));
    }

    @Override
    public void updateAAD(final byte[] input, final int inputOffset, final int inputLen) {
        final int position = inputBufferPosition;
        final int length = inputLen;
        inputBuffer.putBytes(position, input, inputOffset, inputLen);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainAAD(position, length));
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer input) {
        final int position = inputBufferPosition;
        final int length = input.remaining();
        inputBuffer.putBytes(position, input, input.position(), length);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainAAD(position, length));
        ByteBuffers.position(input, input.position() + length);
    }

    @Override
    public void updateAAD(final IByteBuffer input) {
        final int position = inputBufferPosition;
        final int length = input.capacity();
        inputBuffer.putBytes(position, input);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainAAD(position, length));
    }

    private void update(final byte[] input, final int inputOffset, final int inputLen) {
        final int position = inputBufferPosition;
        final int length = inputLen;
        inputBuffer.putBytes(position, input, inputOffset, inputLen);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainOutput(position, length));
    }

    private void update(final java.nio.ByteBuffer input) {
        final int position = inputBufferPosition;
        final int length = input.remaining();
        inputBuffer.putBytes(position, input, input.position(), length);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainOutput(position, length));
        ByteBuffers.position(input, input.position() + length);
    }

    private void update(final IByteBuffer input) {
        final int position = inputBufferPosition;
        final int length = input.capacity();
        inputBuffer.putBytes(position, input);
        inputBufferPosition += length;
        inputBufferTasks.add(() -> drainOutput(position, length));
    }

    private void drainOutput(final int position, final int length) {
        final int toIndex = position + length;
        final int limitedToIndex = Integers.min(toIndex, getInputBufferLimit());
        final int limitedLength = limitedToIndex - position;
        if (limitedLength < 0) {
            return;
        }
        final int written = getDelegate().update(inputBuffer.slice(position, limitedLength),
                outputBuffer.sliceFrom(outputBufferPosition));
        outputBufferPosition += written;
    }

    private void drainAAD(final int position, final int length) {
        final int toIndex = position + length;
        final int limitedToIndex = Integers.min(toIndex, getInputBufferLimit());
        final int limitedLength = limitedToIndex - position;
        if (limitedLength < 0) {
            return;
        }
        getDelegate().updateAAD(inputBuffer.slice(position, limitedLength));
    }

    private int getInputBufferLimit() {
        if (getHash().isDynamicHashSize()) {
            final int hashSize = inputBuffer.getInt(inputBufferPosition - Integer.BYTES);
            return inputBufferPosition - hashSize - Integer.BYTES;
        } else {
            return inputBufferPosition - getHash().getHashSize();
        }

    }

    @Override
    public void close() {
    }

    void reset() {
        inputBufferPosition = 0;
        inputBufferTasks.clear();
        outputBufferPosition = 0;
    }

}
