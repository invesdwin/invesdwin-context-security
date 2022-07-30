package de.invesdwin.context.security.crypto.verification.hash;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.context.security.crypto.verification.VerificationDelegateSerde;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.stream.ChannelLayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.ChannelLayeredHashOutputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashOutputStream;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class HashVerificationFactory implements IVerificationFactory {

    private final IHashAlgorithm algorithm;
    private final Key key;

    public HashVerificationFactory(final byte[] key) {
        this(IHashAlgorithm.DEFAULT, key);
    }

    public HashVerificationFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(IHashAlgorithm.DEFAULT, derivedKeyProvider);
    }

    public HashVerificationFactory(final IHashAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKey("hash-key".getBytes(), algorithm.getHashSize()));
    }

    public HashVerificationFactory(final IHashAlgorithm algorithm, final byte[] key) {
        this.algorithm = algorithm;
        this.key = algorithm.wrapKey(key);
    }

    @Override
    public IHashAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public void init(final IHash hash) {
        hash.init(key);
    }

    @Override
    public LayeredHashOutputStream newHashOutputStream(final OutputStream out) {
        return ChannelLayeredHashOutputStream.maybeWrap(out, algorithm.newHash(), key);
    }

    @Override
    public LayeredHashInputStream newHashInputStream(final InputStream in) {
        return ChannelLayeredHashInputStream.maybeWrap(in, algorithm.newHash(), key);
    }

    @Override
    public byte[] newHash(final IByteBuffer src) {
        final IHash hash = algorithm.getHashPool().borrowObject();
        try {
            return newHash(src, hash);
        } finally {
            algorithm.getHashPool().returnObject(hash);
        }
    }

    @Override
    public byte[] newHash(final IByteBuffer src, final IHash hash) {
        init(hash);
        hash.update(src);
        return hash.doFinal();
    }

    @Override
    public int putHash(final IByteBuffer dest, final int destSignatureIndex) {
        final IHash hash = algorithm.getHashPool().borrowObject();
        try {
            return putHash(dest, destSignatureIndex, hash);
        } finally {
            algorithm.getHashPool().returnObject(hash);
        }
    }

    @Override
    public int putHash(final IByteBuffer dest, final int destSignatureIndex, final IHash hash) {
        final byte[] signature = newHash(dest.sliceTo(destSignatureIndex), hash);
        dest.putBytes(destSignatureIndex, signature);
        return signature.length;
    }

    @Override
    public int copyAndHash(final IByteBuffer src, final IByteBuffer dest) {
        final IHash hash = algorithm.getHashPool().borrowObject();
        try {
            return copyAndHash(src, dest, hash);
        } finally {
            algorithm.getHashPool().returnObject(hash);
        }
    }

    @Override
    public int copyAndHash(final IByteBuffer src, final IByteBuffer dest, final IHash hash) {
        init(hash);
        hash.update(src);
        final byte[] signature = hash.doFinal();
        dest.putBytes(0, src);
        final int signatureIndex = src.capacity();
        dest.putBytes(signatureIndex, signature);
        return signatureIndex + signature.length;
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest) {
        final IHash hash = algorithm.getHashPool().borrowObject();
        try {
            return verifyAndCopy(src, dest, hash);
        } finally {
            algorithm.getHashPool().returnObject(hash);
        }
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IHash hash) {
        final IByteBuffer payloadBuffer = verifyAndSlice(src, hash);
        dest.putBytes(0, payloadBuffer);
        return payloadBuffer.capacity();
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src) {
        final IHash hash = algorithm.getHashPool().borrowObject();
        try {
            return verifyAndSlice(src, hash);
        } finally {
            algorithm.getHashPool().returnObject(hash);
        }
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src, final IHash hash) {
        init(hash);
        final IByteBuffer payloadBuffer = hash.verifyAndSlice(src);
        return payloadBuffer;
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return new VerificationDelegateSerde<>(delegate, this);
    }

}
