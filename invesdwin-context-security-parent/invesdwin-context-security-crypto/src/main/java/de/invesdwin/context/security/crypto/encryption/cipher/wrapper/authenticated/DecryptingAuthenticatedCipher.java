package de.invesdwin.context.security.crypto.encryption.cipher.wrapper.authenticated;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.NoSuchElementException;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.collections.iterable.buffer.BufferingIterator;
import de.invesdwin.util.collections.iterable.buffer.IBufferingIterator;
import de.invesdwin.util.math.Integers;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.EmptyByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class DecryptingAuthenticatedCipher implements ICipher {

    private final ICipher delegate;
    private final IAuthenticationFactory authenticationFactory;
    private final IMac mac;

    /**
     * We have to verify everything before starting with the decryption:
     * https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html
     */
    private final IByteBuffer inputBuffer = ByteBuffers.allocateExpandable();
    private final IBufferingIterator<Runnable> inputBufferTasks = new BufferingIterator<>();
    private int inputBufferPosition = 0;

    private final IByteBuffer outputBuffer = ByteBuffers.allocateExpandable();
    private int outputBufferPosition = 0;

    public DecryptingAuthenticatedCipher(final ICipher unauthenticatedCipher,
            final IAuthenticationFactory authenticationFactory, final IMac mac) {
        this.delegate = unauthenticatedCipher;
        this.authenticationFactory = authenticationFactory;
        this.mac = mac;
    }

    public ICipher getUnauthenticatedCipher() {
        return delegate;
    }

    public IMac getMac() {
        return mac;
    }

    public IAuthenticationFactory getAuthenticationFactory() {
        return authenticationFactory;
    }

    @Override
    public int getBlockSize() {
        return delegate.getBlockSize();
    }

    @Override
    public int getSignatureSize() {
        return delegate.getSignatureSize() + mac.getMacLength();
    }

    @Override
    public String getAlgorithm() {
        return delegate.getAlgorithm() + "With" + mac.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        if (mode != Cipher.DECRYPT_MODE) {
            throw new IllegalArgumentException("Only decryption supported");
        }
        delegate.init(mode, key, params);
        authenticationFactory.init(mac);
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
        update(inBuffer);
        final IByteBuffer decrypted = verifyAndDrainOutput();
        final int length = decrypted.capacity();
        decrypted.getBytesTo(0, outBuffer, length);
        ByteBuffers.position(outBuffer, outBuffer.position() + length);
        return length;
    }

    @Override
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        update(inBuffer);
        final IByteBuffer decrypted = verifyAndDrainOutput();
        final int length = decrypted.capacity();
        decrypted.getBytesTo(0, outBuffer, length);
        return length;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return doFinal(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        update(input, inputOffset, inputLen);
        return doFinal(output, outputOffset);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        final IByteBuffer decrypted = verifyAndDrainOutput();
        final int outputLength = output.length - offset;
        if (outputLength > decrypted.capacity()) {
            throw new IllegalArgumentException(
                    "Insufficient output length [" + outputLength + "] for required: " + outputBufferPosition);
        }
        decrypted.getBytesFrom(0, output, offset);
        return outputLength;
    }

    private IByteBuffer verifyAndDrainOutput() {
        mac.verifyThrow(inputBuffer.sliceTo(inputBufferPosition));
        try {
            while (true) {
                final Runnable next = inputBufferTasks.next();
                next.run();
            }
        } catch (final NoSuchElementException e) {
            //end reached
        }
        final int written = delegate.doFinal(EmptyByteBuffer.INSTANCE, outputBuffer.sliceFrom(outputBufferPosition));
        outputBufferPosition += written;
        return outputBuffer.sliceTo(outputBufferPosition);
    }

    @Override
    public byte[] doFinal() {
        final IByteBuffer decrypted = verifyAndDrainOutput();
        return decrypted.asByteArrayCopy();
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
        final int written = delegate.update(inputBuffer.slice(position, limitedLength),
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
        delegate.updateAAD(inputBuffer.slice(position, limitedLength));
    }

    private int getInputBufferLimit() {
        return inputBufferPosition - mac.getMacLength();
    }

    @Override
    public void close() {
        delegate.close();
        mac.close();
    }

    void reset() {
        inputBufferPosition = 0;
        inputBufferTasks.clear();
        outputBufferPosition = 0;
    }

}
