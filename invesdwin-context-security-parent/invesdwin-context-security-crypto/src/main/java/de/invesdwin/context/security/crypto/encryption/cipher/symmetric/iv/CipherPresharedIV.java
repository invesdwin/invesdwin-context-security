package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.RefreshingCipherObjectPool;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.util.concurrent.pool.IObjectPool;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Less data on the wire because IV is not stored with the message, but requires the IV to be calculated or preshared
 * from the outside. Each message needs to have its unique IV normally. This can be achieved by mutating the presharedIV
 * byte array reference from the outside.
 */
@Immutable
public class CipherPresharedIV implements ICipherIV {

    private final ISymmetricCipherAlgorithm algorithm;
    private final MutableIvParameterSpec presharedIV;
    private final RefreshingCipherObjectPool cipherPool;

    public CipherPresharedIV(final ISymmetricCipherAlgorithm algorithm, final byte[] presharedIV) {
        this.algorithm = algorithm;
        this.presharedIV = new MutableIvParameterSpec(presharedIV);
        assert presharedIV.length == algorithm.getIvSize() : "iv.length[" + presharedIV.length
                + "] != algorithm.getIvBytes[" + algorithm.getIvSize() + "]";
        //can not reuse IV with AES/GCM/NoPadding, thus create a new instance
        this.cipherPool = new RefreshingCipherObjectPool(algorithm);
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getIvBlockSize() {
        return algorithm.getIvSize();
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
    public IObjectPool<ICipher> getCipherPool() {
        return cipherPool;
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

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        buffer.putBytes(0, presharedIV.getIV());
        return presharedIV.getIV().length;
    }

    @Override
    public ICipherIV fromBuffer(final IByteBuffer buffer) {
        final byte[] presharedIVFromBuffer = buffer.asByteArrayCopy();
        return new CipherPresharedIV(algorithm, presharedIVFromBuffer);
    }

    @Override
    public ICipherIV newRandomInstance() {
        final byte[] randomIV = ByteBuffers.allocateByteArray(presharedIV.getIV().length);
        CipherDerivedIV.randomizeIV(randomIV);
        return new CipherPresharedIV(algorithm, randomIV);
    }

}
