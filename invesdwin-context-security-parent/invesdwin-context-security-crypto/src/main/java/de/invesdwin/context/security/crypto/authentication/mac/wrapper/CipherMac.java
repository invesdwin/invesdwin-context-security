package de.invesdwin.context.security.crypto.authentication.mac.wrapper;

import java.security.Key;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.ICipherIV;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class CipherMac implements IMac {

    private final ICipherAlgorithm algorithm;
    private final ICipher cipher;
    private final ICipherIV cipherIV;
    private Key prevKey;
    private final MutableIvParameterSpec iv;
    private final IByteBuffer ivBlock;
    private final int macLength;

    public CipherMac(final ICipherAlgorithm algorithm, final ICipherIV cipherIV) {
        this.algorithm = algorithm;
        this.cipher = algorithm.newCipher();
        this.cipherIV = cipherIV;
        this.iv = new MutableIvParameterSpec(ByteBuffers.allocateByteArray(algorithm.getIvBytes()));
        this.ivBlock = ByteBuffers.allocate(cipherIV.getBlockSizeIV());
        this.macLength = cipher.getBlockSize() + cipherIV.getBlockSizeIV();
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    @Override
    public int getMacLength() {
        return macLength;
    }

    @Override
    public void init(final Key key) {
        this.prevKey = key;
        reset();
    }

    @Override
    public void update(final IByteBuffer input) {
        cipher.updateAAD(input);
    }

    @Override
    public void update(final byte input) {
        cipher.updateAAD(new byte[] { input });
    }

    @Override
    public void update(final byte[] input) {
        cipher.updateAAD(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        cipher.updateAAD(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        final IByteBuffer buffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
        try {
            final int macLength = getMacLength();
            buffer.ensureCapacity(macLength);
            final int macIndex = cipherIV.getBlockSizeIV();
            buffer.putBytes(0, ivBlock);
            int written = macIndex;
            try {
                written += cipher.doFinal(null, buffer.sliceFrom(macIndex));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
            assert written == macLength : "written [" + written + "] != macLength [" + macLength + "]";
            return buffer.asByteArrayCopy(0, written);
        } finally {
            ByteBuffers.EXPANDABLE_POOL.returnObject(buffer);
        }
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        update(input);
        return doFinal();
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        final int macLength = getMacLength();
        if (output == null || output.length - offset < macLength) {
            throw new RuntimeException(new ShortBufferException("Cannot store MAC in output buffer"));
        }
        final byte[] mac = doFinal();
        System.arraycopy(mac, 0, output, offset, macLength);
        return macLength;
    }

    @Override
    public void reset() {
        cipherIV.putIV(ivBlock, iv);
        cipher.init(Cipher.ENCRYPT_MODE, prevKey, algorithm.wrapIv(iv));
    }

    @Override
    public void close() {
        prevKey = null;
        cipher.close();
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        return verify(ByteBuffers.wrap(input), ByteBuffers.wrap(signature));
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        cipherIV.getIV(input, iv);
        cipher.init(Cipher.ENCRYPT_MODE, prevKey, algorithm.wrapIv(iv));
        update(input);
        final byte[] calculatedSignature;
        try {
            calculatedSignature = cipher.doFinal();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        final int macIndex = cipherIV.getBlockSizeIV();
        return ByteBuffers.constantTimeEquals(signature.sliceFrom(macIndex), calculatedSignature);
    }

}
