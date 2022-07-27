package de.invesdwin.context.security.crypto.encryption.cipher;

import java.io.Closeable;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface ICipher extends Closeable {

    int getBlockSize();

    int getHashSize();

    String getAlgorithm();

    void init(int mode, Key key, AlgorithmParameterSpec params);

    int update(java.nio.ByteBuffer inBuffer, java.nio.ByteBuffer outBuffer);

    default int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final java.nio.ByteBuffer inBufferNio = inBuffer.asNioByteBuffer();
        final java.nio.ByteBuffer outBufferNio = outBuffer.asNioByteBuffer();

        final int inPositionBefore = inBufferNio.position();
        final int outPositionBefore = outBufferNio.position();

        final int length = update(inBufferNio, outBufferNio);

        ByteBuffers.position(inBufferNio, inPositionBefore);
        ByteBuffers.position(outBufferNio, outPositionBefore);

        return length;
    }

    int update(byte[] input, int inputOffset, int inputLen, byte[] output);

    int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

    int doFinal(java.nio.ByteBuffer inBuffer, java.nio.ByteBuffer outBuffer);

    default int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        final java.nio.ByteBuffer inBufferNio = inBuffer.asNioByteBuffer();
        final java.nio.ByteBuffer outBufferNio = outBuffer.asNioByteBuffer();

        final int inPositionBefore = inBufferNio.position();
        final int outPositionBefore = outBufferNio.position();

        final int length = doFinal(inBufferNio, outBufferNio);

        ByteBuffers.position(inBufferNio, inPositionBefore);
        ByteBuffers.position(outBufferNio, outPositionBefore);

        return length;
    }

    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output);

    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

    int doFinal(byte[] output, int offset);

    byte[] doFinal();

    void updateAAD(byte input);

    void updateAAD(byte[] input);

    void updateAAD(byte[] input, int inputOffset, int inputLen);

    void updateAAD(java.nio.ByteBuffer input);

    default void updateAAD(final IByteBuffer input) {
        final java.nio.ByteBuffer inputNio = input.asNioByteBuffer();
        final int positionBefore = inputNio.position();
        updateAAD(inputNio);
        ByteBuffers.position(inputNio, positionBefore);
    }

    @Override
    void close();

}
