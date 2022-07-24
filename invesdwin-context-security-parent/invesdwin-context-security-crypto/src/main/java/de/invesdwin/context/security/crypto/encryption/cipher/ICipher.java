package de.invesdwin.context.security.crypto.encryption.cipher;

import java.io.Closeable;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface ICipher extends Closeable {

    int getBlockSize();

    String getAlgorithm();

    void init(int mode, Key key, AlgorithmParameterSpec params);

    int update(IByteBuffer inBuffer, IByteBuffer outBuffer);

    int update(byte[] input, int inputOffset, int inputLen, byte[] output);

    int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

    int doFinal(IByteBuffer inBuffer, IByteBuffer outBuffer);

    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output);

    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset);

    int doFinal(byte[] output, int offset);

    byte[] doFinal();

    void updateAAD(byte[] aad);

    void updateAAD(byte[] aad, int inputOffset, int inputLen);

    void updateAAD(IByteBuffer aad);

    @Override
    void close();

}
