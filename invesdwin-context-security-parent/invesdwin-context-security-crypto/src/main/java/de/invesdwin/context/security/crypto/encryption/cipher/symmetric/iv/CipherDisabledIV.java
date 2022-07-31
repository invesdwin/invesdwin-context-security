package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public final class CipherDisabledIV implements ICipherIV {

    public static final CipherDisabledIV INSTANCE = new CipherDisabledIV();

    private CipherDisabledIV() {
    }

    @Override
    public AlgorithmParameterSpec wrapParam(final byte[] iv) {
        return null;
    }

    @Override
    public AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
        return null;
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public int getIvBlockSize() {
        return 0;
    }

    @Override
    public int putIV(final IByteBuffer output, final MutableIvParameterSpec destIV) {
        return 0;
    }

    @Override
    public int putIV(final OutputStream output, final MutableIvParameterSpec destIV) {
        return 0;
    }

    @Override
    public void getIV(final IByteBuffer input, final MutableIvParameterSpec destIV) {
    }

    @Override
    public void getIV(final InputStream input, final MutableIvParameterSpec destIV) {
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        return 0;
    }

    @Override
    public ICipherIV fromBuffer(final IByteBuffer buffer) {
        return INSTANCE;
    }

    @Override
    public ICipherIV newRandomInstance() {
        return INSTANCE;
    }

}
