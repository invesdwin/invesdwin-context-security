package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import java.security.Key;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.EmptyByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class SymmetricCipherAadHash implements IHash {

    private final ISymmetricCipherAlgorithm algorithm;
    private final ICipher cipher;
    private final ICipherIV cipherIV;
    private Key prevKey;
    private final MutableIvParameterSpec iv;
    private final IByteBuffer ivBlock;
    private final int hashSize;

    public SymmetricCipherAadHash(final ISymmetricCipherAlgorithm algorithm, final ICipherIV cipherIV) {
        this.algorithm = algorithm;
        this.cipher = algorithm.newCipher();
        this.cipherIV = cipherIV;
        this.iv = new MutableIvParameterSpec(ByteBuffers.allocateByteArray(cipherIV.getIvSize()));
        this.ivBlock = ByteBuffers.allocate(cipherIV.getIvSize());
        this.hashSize = cipher.getHashSize() + cipherIV.getIvSize();
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public void init(final Key key) {
        this.prevKey = key;
        reset();
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        cipher.updateAAD(input);
    }

    @Override
    public void update(final IByteBuffer input) {
        cipher.updateAAD(input);
    }

    @Override
    public void update(final byte input) {
        cipher.updateAAD(input);
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
            buffer.ensureCapacity(hashSize);
            final int macIndex = cipherIV.getIvSize();
            buffer.putBytes(0, ivBlock);
            int written = macIndex;
            try {
                written += cipher.doFinal(EmptyByteBuffer.INSTANCE, buffer.sliceFrom(macIndex));
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
            assert written == hashSize : "written [" + written + "] != hashSize [" + hashSize + "]";
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
        if (output == null || output.length - offset < hashSize) {
            throw new RuntimeException(new ShortBufferException("Cannot store hash in output buffer"));
        }
        final byte[] hash = doFinal();
        System.arraycopy(hash, 0, output, offset, hashSize);
        return hashSize;
    }

    @Override
    public void reset() {
        cipherIV.putIV(ivBlock, iv);
        cipher.init(Cipher.ENCRYPT_MODE, prevKey, algorithm.wrapParam(iv));
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
        cipher.init(Cipher.ENCRYPT_MODE, prevKey, algorithm.wrapParam(iv));
        update(input);
        final byte[] calculatedSignature;
        try {
            calculatedSignature = cipher.doFinal();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        final int macIndex = cipherIV.getIvSize();
        return ByteBuffers.constantTimeEquals(signature.sliceFrom(macIndex), calculatedSignature);
    }

}
