package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.IHashKey;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class JceMacHash implements IHash {

    private final Mac mac;

    public JceMacHash(final String algorithm) {
        this(getJceMacInstance(algorithm));
    }

    public JceMacHash(final Mac mac) {
        this.mac = mac;
    }

    public static Mac getJceMacInstance(final String algorithm) {
        try {
            return Mac.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return mac.getAlgorithm();
    }

    @Override
    public int getHashSize() {
        return mac.getMacLength();
    }

    @Override
    public void init(final HashMode mode, final IKey key) {
        try {
            final IHashKey cKey = (IHashKey) key;
            mac.init(cKey.getKey(mode));
        } catch (final InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void update(final byte input) {
        mac.update(input);
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        mac.update(input);
    }

    @Override
    public void update(final byte[] input) {
        mac.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        mac.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        return mac.doFinal();
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        return mac.doFinal(input);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        try {
            mac.doFinal(output, offset);
            return getHashSize();
        } catch (ShortBufferException | IllegalStateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset() {
        mac.reset();
    }

    @Override
    public void close() {
        mac.reset();
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        update(input);
        final byte[] calculatedSignature = doFinal();
        return ByteBuffers.constantTimeEquals(signature, calculatedSignature);
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        update(input);
        final byte[] calculatedSignature = doFinal();
        return ByteBuffers.constantTimeEquals(signature, calculatedSignature);
    }

}
