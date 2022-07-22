package de.invesdwin.context.security.crypto.authentication;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.mac.IMacAlgorithm;
import de.invesdwin.context.security.crypto.authentication.mac.pool.DisabledMac;
import de.invesdwin.context.security.crypto.authentication.mac.pool.IMac;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacInputStream;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacOutputStream;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import de.invesdwin.util.streams.pool.buffered.PooledFastBufferedOutputStream;

@Immutable
public final class DisabledAuthenticationFactory implements IAuthenticationFactory {

    public static final DisabledAuthenticationFactory INSTANCE = new DisabledAuthenticationFactory();

    private DisabledAuthenticationFactory() {
    }

    @Override
    public IMacAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public LayeredMacOutputStream newSignatureOutputStream(final OutputStream out) {
        //buffering is better for write throughput to file
        return new LayeredMacOutputStream(PooledFastBufferedOutputStream.newInstance(out), DisabledMac.INSTANCE, null);
    }

    @Override
    public LayeredMacInputStream newVerificationInputStream(final InputStream in) {
        return new LayeredMacInputStream(in, DisabledMac.INSTANCE, null);
    }

    @Override
    public byte[] newSignature(final IByteBuffer src) {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public byte[] newSignature(final IByteBuffer src, final IMac mac) {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public int putSignature(final IByteBuffer dest, final int destIndex) {
        return 0;
    }

    @Override
    public int putSignature(final IByteBuffer dest, final int destIndex, final IMac mac) {
        return 0;
    }

    @Override
    public int copyAndSign(final IByteBuffer src, final IByteBuffer dest) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int copyAndSign(final IByteBuffer src, final IByteBuffer dest, final IMac mac) {
        return copyAndSign(src, dest);
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IMac mac) {
        return verifyAndCopy(src, dest);
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src) {
        return src;
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src, final IMac mac) {
        return src;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde) {
        return serde;
    }

}
