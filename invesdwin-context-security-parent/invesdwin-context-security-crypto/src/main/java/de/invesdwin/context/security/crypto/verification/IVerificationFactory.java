package de.invesdwin.context.security.crypto.verification;

import java.io.InputStream;
import java.io.OutputStream;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashOutputStream;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Used to authenticate messages (e.g. with HmacSHA256)
 */
public interface IVerificationFactory {

    IHashAlgorithm getAlgorithm();

    IKey getKey();

    IObjectPool<IHash> getHashPool();

    default LayeredHashOutputStream newHashOutputStream(final OutputStream out) {
        return newHashOutputStream(out, getAlgorithm().newHash());
    }

    default LayeredHashOutputStream newHashOutputStream(final OutputStream out, final IHash hash) {
        return newHashOutputStream(out, hash, getKey());
    }

    LayeredHashOutputStream newHashOutputStream(OutputStream out, IHash hash, IKey key);

    default LayeredHashInputStream newHashInputStream(final InputStream in) {
        return newHashInputStream(in, getAlgorithm().newHash());
    }

    default LayeredHashInputStream newHashInputStream(final InputStream in, final IHash hash) {
        return newHashInputStream(in, hash, getKey());
    }

    LayeredHashInputStream newHashInputStream(InputStream in, IHash hash, IKey key);

    default byte[] newHash(final IByteBuffer src) {
        final IHash hash = getHashPool().borrowObject();
        try {
            return newHash(src, hash);
        } finally {
            getHashPool().returnObject(hash);
        }
    }

    default byte[] newHash(final IByteBuffer src, final IHash hash) {
        return newHash(src, hash, getKey());
    }

    byte[] newHash(IByteBuffer src, IHash hash, IKey key);

    default int putHash(final IByteBuffer dest, final int destSignatureIndex) {
        final IHash hash = getHashPool().borrowObject();
        try {
            return putHash(dest, destSignatureIndex, hash);
        } finally {
            getHashPool().returnObject(hash);
        }
    }

    default int putHash(final IByteBuffer dest, final int destSignatureIndex, final IHash hash) {
        return putHash(dest, destSignatureIndex, hash, getKey());
    }

    int putHash(IByteBuffer dest, int destSignatureIndex, IHash hash, IKey key);

    default int copyAndHash(final IByteBuffer src, final IByteBuffer dest) {
        final IHash hash = getHashPool().borrowObject();
        try {
            return copyAndHash(src, dest, hash);
        } finally {
            getHashPool().returnObject(hash);
        }
    }

    default int copyAndHash(final IByteBuffer src, final IByteBuffer dest, final IHash hash) {
        return copyAndHash(src, dest, hash, getKey());
    }

    int copyAndHash(IByteBuffer src, IByteBuffer dest, IHash hash, IKey key);

    default int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest) {
        final IHash hash = getHashPool().borrowObject();
        try {
            return verifyAndCopy(src, dest, hash);
        } finally {
            getHashPool().returnObject(hash);
        }
    }

    default int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IHash hash) {
        return verifyAndCopy(src, dest, hash, getKey());
    }

    int verifyAndCopy(IByteBuffer src, IByteBuffer dest, IHash hash, IKey key);

    default IByteBuffer verifyAndSlice(final IByteBuffer src) {
        final IHash hash = getHashPool().borrowObject();
        try {
            return verifyAndSlice(src, hash);
        } finally {
            getHashPool().returnObject(hash);
        }
    }

    default IByteBuffer verifyAndSlice(final IByteBuffer src, final IHash hash) {
        return verifyAndSlice(src, hash, getKey());
    }

    IByteBuffer verifyAndSlice(IByteBuffer src, IHash hash, IKey key);

    default <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return maybeWrap(delegate, getKey());
    }

    <T> ISerde<T> maybeWrap(ISerde<T> delegate, IKey key);

}
