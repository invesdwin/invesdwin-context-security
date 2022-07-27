package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import java.security.Key;
import java.util.zip.Checksum;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.math.Integers;
import de.invesdwin.util.math.Longs;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class ChecksumHash implements IHash {

    private final String algorithm;
    private final Checksum checksum;
    private final int hashSize;
    private byte[] prevKey;

    public ChecksumHash(final String algorithm, final Checksum checksum, final int hashSize) {
        this.algorithm = algorithm;
        this.checksum = checksum;
        this.hashSize = hashSize;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getHashSize() {
        return Long.BYTES;
    }

    @Override
    public void init(final Key key) {
        checksum.reset();
        if (key != null) {
            //we use the key as a pepper (static salt)
            final byte[] encoded = key.getEncoded();
            checksum.update(encoded);
            prevKey = encoded;
        } else {
            prevKey = null;
        }
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        checksum.update(input);
    }

    @Override
    public void update(final byte input) {
        checksum.update(input);
    }

    @Override
    public void update(final byte[] input) {
        checksum.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        checksum.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        final long value = checksum.getValue();
        switch (hashSize) {
        case Integer.BYTES:
            return Integers.toByteArray(Integers.checkedCast(value));
        case Long.BYTES:
            return Longs.toByteArray(value);
        default:
            throw UnknownArgumentException.newInstance(int.class, hashSize);
        }
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        update(input);
        return doFinal();
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        final int hashSize = getHashSize();
        if (output == null || output.length - offset < hashSize) {
            throw new RuntimeException(new ShortBufferException("Cannot store MAC in output buffer"));
        }
        final byte[] hash = doFinal();
        System.arraycopy(hash, 0, output, offset, hashSize);
        return hashSize;
    }

    @Override
    public void reset() {
        checksum.reset();
        if (prevKey != null) {
            //we use the key as a salt
            checksum.update(prevKey);
        }
    }

    @Override
    public void close() {
        checksum.reset();
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
