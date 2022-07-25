package de.invesdwin.context.security.crypto.authentication.mac;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public final class DisabledMac implements IMac {

    public static final DisabledMac INSTANCE = new DisabledMac();

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public int getMacLength() {
        return 0;
    }

    @Override
    public void init(final Key key) {
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
    }

    @Override
    public void update(final byte input) {
    }

    @Override
    public void update(final byte[] input) {
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
    }

    @Override
    public byte[] doFinal() {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        return Bytes.EMPTY_ARRAY;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        return 0;
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        return true;
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        return true;
    }

    @Override
    public void reset() {
    }

    @Override
    public void close() {
    }

}
