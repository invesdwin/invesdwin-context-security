package de.invesdwin.context.security.crypto.authentication.mac;

import java.io.Closeable;
import java.security.Key;

import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IMac extends Closeable {

    String getAlgorithm();

    int getMacLength();

    /**
     * This will skip init if the same key is used and do a reset instead if needed.
     * 
     * Params are handled by the implementatio. For example an IV that is randomized on init or an Hmac length that is
     * defined in the constructor of the implementation and then passed as a param.
     */
    void init(Key key);

    void update(IByteBuffer input);

    void update(byte input);

    void update(byte[] input);

    void update(byte[] input, int inputOffset, int inputLen);

    byte[] doFinal();

    byte[] doFinal(byte[] input);

    int doFinal(byte[] output, int offset);

    default boolean verify(final byte[] signedInput) {
        final IByteBuffer buffer = ByteBuffers.wrap(signedInput);
        return verify(buffer);
    }

    default void verifyThrow(final byte[] signedInput) {
        if (!verify(signedInput)) {
            throw new IllegalArgumentException("Signature mismatch");
        }
    }

    boolean verify(byte[] input, byte[] signature);

    default void verifyThrow(final byte[] input, final byte[] signature) {
        if (!verify(input, signature)) {
            throw new IllegalArgumentException("Signature mismatch");
        }
    }

    default boolean verify(final IByteBuffer signedInput) {
        final int signatureIndex = signedInput.remaining(getMacLength());
        final IByteBuffer input = signedInput.newSlice(0, signatureIndex);
        final IByteBuffer signature = signedInput.sliceFrom(signatureIndex);
        return verify(input, signature);
    }

    default IByteBuffer verifyAndSlice(final IByteBuffer signedInput) {
        final int signatureIndex = signedInput.remaining(getMacLength());
        final IByteBuffer input = signedInput.newSlice(0, signatureIndex);
        final IByteBuffer signature = signedInput.sliceFrom(signatureIndex);
        if (!verify(input, signature)) {
            throw new IllegalArgumentException("Signature mismatch");
        }
        return input;
    }

    boolean verify(IByteBuffer input, IByteBuffer signature);

    default void verifyThrow(final IByteBuffer input, final IByteBuffer signature) {
        if (!verify(input, signature)) {
            throw new IllegalArgumentException("Signature mismatch");
        }
    }

    /**
     * Will only reset if needed (pending update data without a reset, doFinal or init call afterwards)
     */
    void reset();

    @Override
    void close();

}
