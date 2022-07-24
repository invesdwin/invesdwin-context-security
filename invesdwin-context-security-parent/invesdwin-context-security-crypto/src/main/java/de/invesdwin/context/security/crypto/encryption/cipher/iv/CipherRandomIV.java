package de.invesdwin.context.security.crypto.encryption.cipher.iv;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.util.streams.InputStreams;
import de.invesdwin.util.streams.OutputStreams;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Slowest but most secure IV generation with a secure random.
 */
@Immutable
public class CipherRandomIV implements ICipherIV {

    private final ICipherAlgorithm algorithm;

    public CipherRandomIV(final ICipherAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getBlockSizeIV() {
        return algorithm.getIvBytes();
    }

    protected void randomizeIV(final byte[] iv) {
        CipherDerivedIV.randomizeIV(iv);
    }

    @Override
    public int putIV(final IByteBuffer output, final MutableIvParameterSpec destIV) {
        final byte[] iv = destIV.getIV();
        randomizeIV(iv);
        output.putBytes(0, iv);
        return iv.length;
    }

    @Override
    public int putIV(final OutputStream output, final MutableIvParameterSpec destIV) {
        final byte[] iv = destIV.getIV();
        randomizeIV(iv);
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
