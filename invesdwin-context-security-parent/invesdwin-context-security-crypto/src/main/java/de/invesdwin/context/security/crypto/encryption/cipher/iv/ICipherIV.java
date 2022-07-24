package de.invesdwin.context.security.crypto.encryption.cipher.iv;

import java.io.InputStream;
import java.io.OutputStream;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface ICipherIV {

    ICipherAlgorithm getAlgorithm();

    int getBlockSizeIV();

    int putIV(IByteBuffer output, MutableIvParameterSpec destIV);

    int putIV(OutputStream output, MutableIvParameterSpec destIV);

    void getIV(IByteBuffer input, MutableIvParameterSpec destIV);

    void getIV(InputStream input, MutableIvParameterSpec destIV);

    default MutableIvParameterSpec borrowDestIV() {
        return getAlgorithm().getIvParameterSpecPool().borrowObject();
    }

    default void returnDestIV(final MutableIvParameterSpec iv) {
        getAlgorithm().getIvParameterSpecPool().returnObject(iv);
    }

    default byte[] putNewIV(final IByteBuffer out) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvBytes()));
        putIV(out, newIv);
        return newIv.getIV();
    }

    default byte[] putNewIV(final OutputStream out) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvBytes()));
        putIV(out, newIv);
        return newIv.getIV();
    }

    default byte[] getNewIV(final IByteBuffer in) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvBytes()));
        getIV(in, newIv);
        return newIv.getIV();
    }

    default byte[] getNewIV(final InputStream in) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvBytes()));
        getIV(in, newIv);
        return newIv.getIV();
    }

}