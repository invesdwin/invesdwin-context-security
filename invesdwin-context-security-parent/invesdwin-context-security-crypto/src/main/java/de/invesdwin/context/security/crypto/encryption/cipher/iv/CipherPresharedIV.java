package de.invesdwin.context.security.crypto.encryption.cipher.iv;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Less data on the wire because IV is not stored with the message, but requires the IV to be calculated or preshared
 * from the outside. Each message needs to have its unique IV normally. This can be achieved by mutating the presharedIV
 * byte array reference from the outside.
 */
@Immutable
public class CipherPresharedIV implements ICipherIV {

    private final ICipherAlgorithm algorithm;
    private final MutableIvParameterSpec presharedIV;

    public CipherPresharedIV(final ICipherAlgorithm algorithm, final byte[] presharedIV) {
        this.algorithm = algorithm;
        this.presharedIV = new MutableIvParameterSpec(presharedIV);
        assert presharedIV.length == algorithm.getIvSize() : "iv.length[" + presharedIV.length
                + "] != algorithm.getIvBytes[" + algorithm.getIvSize() + "]";
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getBlockSizeIV() {
        return 0;
    }

    @Override
    public int putIV(final IByteBuffer output, final MutableIvParameterSpec destIV) {
        return 0;
    }

    @Override
    public int putIV(final OutputStream output, final MutableIvParameterSpec destIV) {
        return 0;
    }

    @Override
    public void getIV(final IByteBuffer input, final MutableIvParameterSpec destIV) {
    }

    @Override
    public void getIV(final InputStream input, final MutableIvParameterSpec destIV) {
    }

    @Override
    public MutableIvParameterSpec borrowDestIV() {
        return presharedIV;
    }

    @Override
    public void returnDestIV(final MutableIvParameterSpec iv) {
        //noop
    }

    @Override
    public byte[] putNewIV(final IByteBuffer out) {
        return presharedIV.getIV();
    }

    @Override
    public byte[] putNewIV(final OutputStream out) {
        return presharedIV.getIV();
    }

    @Override
    public byte[] getNewIV(final IByteBuffer in) {
        return presharedIV.getIV();
    }

    @Override
    public byte[] getNewIV(final InputStream in) {
        return presharedIV.getIV();
    }

}
