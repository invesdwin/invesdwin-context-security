package de.invesdwin.context.security.crypto.encryption.cipher.iv;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.util.streams.InputStreams;
import de.invesdwin.util.streams.OutputStreams;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Counted IV has a good speed while sending the IV over the wire for interoperability. This is not as secure as the
 * derived IV version.
 */
@NotThreadSafe
public class CipherCountedIV implements ICipherIV {

    private final ICipherAlgorithm algorithm;
    private final byte[] initIV;
    private final AtomicLong ivCounter;

    public CipherCountedIV(final ICipherAlgorithm algorithm) {
        this.algorithm = algorithm;
        this.initIV = newInitIV(algorithm.getIvBytes());
        assert initIV.length == algorithm.getIvBytes() : "initIV.length[" + initIV.length + "] != algorithm.getIvBytes["
                + algorithm.getIvBytes() + "]";
        this.ivCounter = newIvCounter();
    }

    protected AtomicLong newIvCounter() {
        return CipherDerivedIV.newRandomIvCounter();
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getBlockSizeIV() {
        return algorithm.getIvBytes();
    }

    protected byte[] newInitIV(final int ivBytes) {
        return CipherDerivedIV.newRandomIV(ivBytes);
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

}
