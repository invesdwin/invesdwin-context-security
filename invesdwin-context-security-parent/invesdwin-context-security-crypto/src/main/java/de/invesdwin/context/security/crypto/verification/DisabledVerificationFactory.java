package de.invesdwin.context.security.crypto.verification;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.DisabledHash;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.stream.ChannelLayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.ChannelLayeredHashOutputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashOutputStream;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.concurrent.pool.SingletonObjectPool;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public final class DisabledVerificationFactory implements IVerificationFactory {

    public static final DisabledVerificationFactory INSTANCE = new DisabledVerificationFactory();
    private final SingletonObjectPool<IHash> hashPool;

    private DisabledVerificationFactory() {
        this.hashPool = new SingletonObjectPool<>(DisabledHash.INSTANCE);
    }

    @Override
    public IHashAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public IKey getKey() {
        return null;
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

    @Override
    public LayeredHashOutputStream newHashOutputStream(final OutputStream out, final IHash hash, final IKey key) {
        return ChannelLayeredHashOutputStream.maybeWrap(out, hash, key);
    }

    @Override
    public LayeredHashInputStream newHashInputStream(final InputStream in, final IHash hash, final IKey key) {
        return ChannelLayeredHashInputStream.maybeWrap(in, hash, key);
    }

    @Override
    public byte[] newHash(final IByteBuffer src, final IHash hash, final IKey key) {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public int putHash(final IByteBuffer dest, final int destIndex, final IHash hash, final IKey key) {
        return 0;
    }

    @Override
    public int copyAndHash(final IByteBuffer src, final IByteBuffer dest, final IHash hash, final IKey key) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IHash hash, final IKey key) {
        dest.putBytes(0, src);
        return src.capacity();
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src, final IHash hash, final IKey key) {
        return src;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde, final IKey key) {
        return serde;
    }

}
