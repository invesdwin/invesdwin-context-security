package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.util.streams.InputStreams;
import de.invesdwin.util.streams.OutputStreams;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Slowest but most secure IV generation with a secure random.
 */
@Immutable
public class CipherRandomIV implements ICipherIV {

    private final ISymmetricCipherAlgorithm algorithm;

    public CipherRandomIV(final ISymmetricCipherAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIvBlockSize() {
        return algorithm.getIvSize();
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

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        //random iv is sent over the wire anyway with each encryption
        return 0;
    }

    @Override
    public ICipherIV fromBuffer(final IByteBuffer buffer) {
        return this;
    }

    @Override
    public ICipherIV newRandomInstance() {
        //this is random anyway
        return this;
    }

}
