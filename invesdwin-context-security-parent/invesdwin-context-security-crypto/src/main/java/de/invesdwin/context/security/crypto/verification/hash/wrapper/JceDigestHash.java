package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import java.security.DigestException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class JceDigestHash implements IHash {

    private final MessageDigest digest;
    private byte[] prevKey;

    public JceDigestHash(final String algorithm) {
        this(getJceDigestInstance(algorithm));
    }

    public JceDigestHash(final MessageDigest digest) {
        this.digest = digest;
    }

    public static MessageDigest getJceDigestInstance(final String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return digest.getAlgorithm();
    }

    @Override
    public int getHashSize() {
        return digest.getDigestLength();
    }

    @Override
    public void init(final Key key) {
        digest.reset();
        if (key != null) {
            //we use the key as a pepper (static salt)
            final byte[] encoded = key.getEncoded();
            digest.update(encoded);
            prevKey = encoded;
        } else {
            prevKey = null;
        }
    }

    @Override
    public void update(final byte input) {
        digest.update(input);
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        digest.update(input);
    }

    @Override
    public void update(final byte[] input) {
        digest.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        digest.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        return digest.digest();
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        return digest.digest(input);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        try {
            digest.digest(output, offset, getHashSize());
            return getHashSize();
        } catch (final DigestException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset() {
        digest.reset();
        if (prevKey != null) {
            //we use the key as a salt
            digest.update(prevKey);
        }
    }

    @Override
    public void close() {
        digest.reset();
        prevKey = null;
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
