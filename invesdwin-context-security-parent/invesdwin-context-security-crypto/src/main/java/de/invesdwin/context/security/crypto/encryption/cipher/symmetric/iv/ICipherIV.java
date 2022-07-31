package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface ICipherIV {

    ISymmetricCipherAlgorithm getAlgorithm();

    default AlgorithmParameterSpec wrapParam(final byte[] iv) {
        return getAlgorithm().wrapParam(iv);
    }

    default AlgorithmParameterSpec wrapParam(final MutableIvParameterSpec iv) {
        return getAlgorithm().wrapParam(iv);
    }

    int getIvBlockSize();

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

    default IObjectPool<ICipher> getCipherPool() {
        return getAlgorithm().getCipherPool();
    }

    default byte[] putNewIV(final IByteBuffer out) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvSize()));
        putIV(out, newIv);
        return newIv.getIV();
    }

    default byte[] putNewIV(final OutputStream out) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvSize()));
        putIV(out, newIv);
        return newIv.getIV();
    }

    default byte[] getNewIV(final IByteBuffer in) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvSize()));
        getIV(in, newIv);
        return newIv.getIV();
    }

    default byte[] getNewIV(final InputStream in) {
        final MutableIvParameterSpec newIv = new MutableIvParameterSpec(
                ByteBuffers.allocateByteArray(getAlgorithm().getIvSize()));
        getIV(in, newIv);
        return newIv.getIV();
    }

}
