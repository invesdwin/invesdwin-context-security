package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.math.Longs;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import io.whitfin.siphash.SipHasher;
import io.whitfin.siphash.SipHasherStream;

@NotThreadSafe
public class SipHasherStreamHash implements IHash {

    private final int c;
    private final int d;
    private final int hashSize;
    private HashMode prevMode;
    private IKey prevKey;
    private SipHasherStream stream;

    public SipHasherStreamHash(final int c, final int d, final int hashSize) {
        this.c = c;
        this.d = d;
        this.hashSize = hashSize;
    }

    @Override
    public String getAlgorithm() {
        return "SipHash-" + c + "-" + d;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public void init(final HashMode mode, final IKey key) {
        this.prevMode = mode;
        this.prevKey = key;
        stream = SipHasher.init(key.toBytes(), c, d);
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        while (input.hasRemaining()) {
            stream.update(input.get());
        }
    }

    @Override
    public void update(final byte input) {
        stream.update(input);
    }

    @Override
    public void update(final byte[] input) {
        stream.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        final int limit = inputOffset + inputLen;
        for (int i = inputLen; i < limit; i++) {
            stream.update(input[i]);
        }
    }

    @Override
    public byte[] doFinal() {
        final long digest = stream.digest();
        return Longs.toByteArray(digest);
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

    @Override
    public void reset() {
        init(prevMode, prevKey);
    }

    @Override
    public void close() {
        stream = null;
        prevMode = null;
        prevKey = null;
    }

}
