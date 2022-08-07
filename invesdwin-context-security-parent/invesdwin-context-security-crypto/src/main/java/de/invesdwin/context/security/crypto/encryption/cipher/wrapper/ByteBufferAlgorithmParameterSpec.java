package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class ByteBufferAlgorithmParameterSpec implements AlgorithmParameterSpec {

    private final IByteBuffer buffer;
    private int size;

    public ByteBufferAlgorithmParameterSpec(final IByteBuffer buffer) {
        this.buffer = buffer;
    }

    public IByteBuffer getBuffer() {
        return buffer;
    }

    public void setSize(final int size) {
        this.size = size;
    }

    public int getSize() {
        return size;
    }

}
