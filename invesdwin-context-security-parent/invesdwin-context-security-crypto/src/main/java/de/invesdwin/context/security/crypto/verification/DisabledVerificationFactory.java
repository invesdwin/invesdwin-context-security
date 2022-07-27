package de.invesdwin.context.security.crypto.verification;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.DisabledHash;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashOutputStream;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import de.invesdwin.util.streams.pool.buffered.PooledFastBufferedOutputStream;

@Immutable
public final class DisabledVerificationFactory implements IVerificationFactory {

    public static final DisabledVerificationFactory INSTANCE = new DisabledVerificationFactory();

    private DisabledVerificationFactory() {
    }

    @Override
    public IHashAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public void init(final IHash hash) {
    }

    @Override
    public LayeredHashOutputStream newHashOutputStream(final OutputStream out) {
        //buffering is better for write throughput to file
        return new LayeredHashOutputStream(PooledFastBufferedOutputStream.newInstance(out), DisabledHash.INSTANCE,
                null);
    }

    @Override
    public LayeredHashInputStream newHashInputStream(final InputStream in) {
        return new LayeredHashInputStream(in, DisabledHash.INSTANCE, null);
    }

    @Override
    public byte[] newHash(final IByteBuffer src) {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public byte[] newHash(final IByteBuffer src, final IHash hash) {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public int putHash(final IByteBuffer dest, final int destIndex) {
        return 0;
    }

    @Override
    public int putHash(final IByteBuffer dest, final int destIndex, final IHash hash) {
        return 0;
    }

    @Override
    public int copyAndHash(final IByteBuffer src, final IByteBuffer dest) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int copyAndHash(final IByteBuffer src, final IByteBuffer dest, final IHash hash) {
        return copyAndHash(src, dest);
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IHash hash) {
        return verifyAndCopy(src, dest);
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src) {
        return src;
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src, final IHash hash) {
        return src;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde) {
        return serde;
    }

}
