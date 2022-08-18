package de.invesdwin.context.security.crypto.verification.signature;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.context.security.crypto.verification.VerificationDelegateSerde;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.stream.ChannelLayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.ChannelLayeredHashOutputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashOutputStream;
import de.invesdwin.context.security.crypto.verification.signature.algorithm.ISignatureAlgorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class SignatureVerificationFactory implements IVerificationFactory {

    private final ISignatureAlgorithm algorithm;
    private final SignatureKey key;

    public SignatureVerificationFactory(final byte[] verifyKey, final byte[] signKey, final int keySizeBits) {
        this(ISignatureAlgorithm.getDefault(), verifyKey, signKey, keySizeBits);
    }

    public SignatureVerificationFactory(final ISignatureAlgorithm algorithm, final byte[] verifyKey,
            final byte[] signKey, final int keySizeBits) {
        this(new SignatureKey(algorithm, verifyKey, signKey, keySizeBits));
    }

    public SignatureVerificationFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(ISignatureAlgorithm.getDefault(), derivedKeyProvider);
    }

    public SignatureVerificationFactory(final ISignatureAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        this(new SignatureKey(algorithm, derivedKeyProvider));
    }

    public SignatureVerificationFactory(final ISignatureAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider, final int derivedKeySizeBits) {
        this(new SignatureKey(algorithm, derivedKeyProvider, derivedKeySizeBits));
    }

    public SignatureVerificationFactory(final SignatureKey key) {
        this.algorithm = key.getAlgorithm();
        this.key = key;
    }

    @Override
    public ISignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return algorithm.getHashPool();
    }

    @Override
    public SignatureKey getKey() {
        return key;
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
        hash.init(HashMode.Sign, key);
        hash.update(src);
        return hash.doFinal();
    }

    @Override
    public int putHash(final IByteBuffer dest, final int destSignatureIndex, final IHash hash, final IKey key) {
        final byte[] signature = newHash(dest.sliceTo(destSignatureIndex), hash, key);
        dest.putBytes(destSignatureIndex, signature);
        return signature.length;
    }

    @Override
    public int copyAndHash(final IByteBuffer src, final IByteBuffer dest, final IHash hash, final IKey key) {
        hash.init(HashMode.Sign, key);
        hash.update(src);
        final byte[] signature = hash.doFinal();
        dest.putBytes(0, src);
        final int signatureIndex = src.capacity();
        dest.putBytes(signatureIndex, signature);
        return signatureIndex + signature.length;
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IHash hash, final IKey key) {
        final IByteBuffer payloadBuffer = verifyAndSlice(src, hash, key);
        dest.putBytes(0, payloadBuffer);
        return payloadBuffer.capacity();
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src, final IHash hash, final IKey key) {
        hash.init(HashMode.Verify, key);
        final IByteBuffer payloadBuffer = hash.verifyAndSlice(src);
        return payloadBuffer;
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate, final IKey key) {
        return new VerificationDelegateSerde<>(delegate, this, key);
    }

}
