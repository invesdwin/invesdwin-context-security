package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.util.streams.InputStreams;
import de.invesdwin.util.streams.OutputStreams;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Counted IV has a good speed while sending the IV over the wire for interoperability. This is not as secure as the
 * derived IV version.
 */
@NotThreadSafe
public class CipherCountedIV implements ICipherIV {

    private final ISymmetricCipherAlgorithm algorithm;
    private final byte[] initIV;
    private final AtomicLong ivCounter;

    public CipherCountedIV(final ISymmetricCipherAlgorithm algorithm) {
        this(algorithm, CipherDerivedIV.newRandomIV(algorithm.getIvSize()));
    }

    public CipherCountedIV(final ISymmetricCipherAlgorithm algorithm, final byte[] initIV) {
        this(algorithm, initIV, CipherDerivedIV.newRandomIvCounter());
    }

    public CipherCountedIV(final ISymmetricCipherAlgorithm algorithm, final byte[] initIV, final AtomicLong ivCounter) {
        this.algorithm = algorithm;
        this.initIV = initIV;
        assert initIV.length == algorithm.getIvSize() : "initIV.length[" + initIV.length + "] != algorithm.getIvBytes["
                + algorithm.getIvSize() + "]";
        this.ivCounter = ivCounter;
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIvBlockSize() {
        return algorithm.getIvSize();
    }

    protected void deriveIV(final byte[] initIV, final long counter, final byte[] iv) {
        CipherDerivedIV.calculateIV(initIV, counter, iv);
    }

    @Override
    public int putIV(final IByteBuffer output, final MutableIvParameterSpec destIV) {
        final long counter = ivCounter.incrementAndGet();
        final byte[] iv = destIV.getIV();
        deriveIV(initIV, counter, iv);
        output.putBytes(0, iv);
        return iv.length;
    }

    @Override
    public int putIV(final OutputStream output, final MutableIvParameterSpec destIV) {
        final long counter = ivCounter.incrementAndGet();
        final byte[] iv = destIV.getIV();
        deriveIV(initIV, counter, iv);
        try {
            OutputStreams.write(output, iv);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
        return iv.length;
    }

    @Override
    public void getIV(final IByteBuffer input, final MutableIvParameterSpec destIV) {
        input.getBytes(0, destIV.getIV());
    }

    @Override
    public void getIV(final InputStream input, final MutableIvParameterSpec destIV) {
        try {
            InputStreams.read(input, destIV.getIV());
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        buffer.putBytes(0, initIV);
        return initIV.length;
    }

    @Override
    public ICipherIV fromBuffer(final IByteBuffer buffer) {
        //counted IV is sent over the wire anyway with each encryption, so we only need initIV
        final byte[] initIVFromBuffer = buffer.asByteArrayCopy();
        return new CipherCountedIV(algorithm, initIVFromBuffer);
    }

    @Override
    public ICipherIV newRandomInstance() {
        //initializes a new random initIV and ivCounter
        return new CipherCountedIV(algorithm);
    }

}
