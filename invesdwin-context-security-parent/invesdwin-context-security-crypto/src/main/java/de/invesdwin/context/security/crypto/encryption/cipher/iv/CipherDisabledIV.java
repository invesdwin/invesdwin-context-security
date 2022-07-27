package de.invesdwin.context.security.crypto.encryption.cipher.iv;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public final class CipherDisabledIV implements ICipherIV {

    public static final CipherDisabledIV INSTANCE = new CipherDisabledIV();

    private CipherDisabledIV() {
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public int getBlockSizeIV() {
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

}
