package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricCipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.IHashKey;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.EmptyByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class SymmetricCipherHashAad implements IHash {

    private final ISymmetricCipherAlgorithm algorithm;
    private final ICipher cipher;
    private final ICipherIV cipherIV;
    private IKey prevKey;
    private IKey prevSymmetricKey;
    private final MutableIvParameterSpec iv;
    private final IByteBuffer ivBlock;
    private final int hashSize;

    public SymmetricCipherHashAad(final ISymmetricCipherAlgorithm algorithm, final ICipherIV cipherIV) {
        this.algorithm = algorithm;
        this.cipher = algorithm.newCipher();
        this.cipherIV = cipherIV;
        this.iv = new MutableIvParameterSpec(ByteBuffers.allocateByteArray(cipherIV.getAlgorithm().getIvSize()));
        this.ivBlock = ByteBuffers.allocate(cipherIV.getIvBlockSize());
        this.hashSize = cipher.getHashSize() + cipherIV.getIvBlockSize();
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    @Override
    public boolean isDynamicHashSize() {
        return false;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public void init(final HashMode mode, final IKey key) {
        if (key != prevKey) {
            this.prevKey = key;
            final IHashKey cKey = (IHashKey) key;
            this.prevSymmetricKey = new SymmetricCipherKey(cipherIV.getAlgorithm(), cKey.getKey(mode), cipherIV);
        }
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
        final IByteBuffer buffer = ByteBuffers.allocate(hashSize);
        final int macIndex = cipherIV.getIvBlockSize();
        buffer.putBytes(0, ivBlock);
        int written = macIndex;
        try {
            written += cipher.doFinal(EmptyByteBuffer.INSTANCE, buffer.sliceFrom(macIndex));
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        assert written == hashSize : "written [" + written + "] != hashSize [" + hashSize + "]";
        return buffer.asByteArray(0, written);
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

    @SuppressWarnings("deprecation")
    @Override
    public void reset() {
        cipherIV.putIV(ivBlock, iv);
        cipher.init(CipherMode.Encrypt, prevSymmetricKey, cipherIV.wrapParam(iv));
    }

    @Override
    public void close() {
        prevKey = null;
        prevSymmetricKey = null;
        cipher.close();
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        return verify(ByteBuffers.wrap(input), ByteBuffers.wrap(signature));
    }

    /**
     * https://stackoverflow.com/questions/48548394/how-to-verify-a-gmac
     */
    @SuppressWarnings("deprecation")
    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        /*
         * this variant would be slower due to exception stack trace generation, though it might better support encoded
         * random elements in the underlying hash (not needed for gmac)
         */
        //        cipherIV.getIV(signature, iv);
        //        cipher.init(Cipher.DECRYPT_MODE, prevKey, cipherIV.wrapParam(iv));
        //        update(input);
        //        try {
        //            final int macIndex = cipherIV.getIvSize();
        //            cipher.doFinal(signature.sliceFrom(macIndex), EmptyByteBuffer.INSTANCE);
        //            return true;
        //        } catch (final Throwable e) {
        //            return false;
        //        }

        cipherIV.getIV(signature, iv);
        cipher.init(CipherMode.Encrypt, prevSymmetricKey, cipherIV.wrapParam(iv));
        update(input);
        final byte[] calculatedSignature;
        try {
            calculatedSignature = cipher.doFinal();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        final int macIndex = cipherIV.getIvBlockSize();
        return ByteBuffers.constantTimeEquals(signature.sliceFrom(macIndex), calculatedSignature);
    }

}
