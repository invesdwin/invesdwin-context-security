package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import java.security.Key;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Cipher;

import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Adapted from org.bouncycastle.crypto.macs.CMac
 * 
 * Similar: https://github.com/devlaam/lora_simulator/blob/master/src/main/java/AesCmac.java
 */
@NotThreadSafe
public class SymmetricCipherHash implements IHash {
    private static final ISO7816d4Padding PADDING = new ISO7816d4Padding();
    private final byte[] poly;
    private final byte[] zeroes;

    private final IByteBuffer mac;

    private final IByteBuffer buf;
    private int bufOff;
    private final ICipher cipher;

    private final int blockSize;
    private final int hashSize;

    private final byte[] l, lu1, lu2;

    private final MutableIvParameterSpec iv;
    private final IByteBuffer ivBlock;
    private final ICipherIV cipherIV;
    private Key prevKey;

    public SymmetricCipherHash(final ICipher cipher, final ICipherIV cipherIV) {
        this.cipher = cipher;
        this.hashSize = cipher.getBlockSize() + cipher.getHashSize() + cipherIV.getIvSize();
        this.blockSize = cipher.getBlockSize();
        this.poly = lookupPoly(blockSize);

        this.mac = ByteBuffers.allocate(blockSize);
        this.buf = ByteBuffers.allocate(blockSize);
        this.zeroes = new byte[blockSize];
        this.bufOff = 0;

        this.l = new byte[blockSize];
        this.lu1 = new byte[blockSize];
        this.lu2 = new byte[blockSize];

        this.iv = new MutableIvParameterSpec(ByteBuffers.allocateByteArray(cipherIV.getIvSize()));
        this.ivBlock = ByteBuffers.allocate(cipherIV.getIvSize());
        this.cipherIV = cipherIV;
    }

    @Override
    public String getAlgorithm() {
        return cipher.getAlgorithm();
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    private static int shiftLeft(final byte[] block, final byte[] output) {
        int i = block.length;
        int bit = 0;
        while (--i >= 0) {
            final int b = block[i] & 0xff;
            output[i] = (byte) ((b << 1) | bit);
            bit = (b >>> 7) & 1;
        }
        return bit;
    }

    private void doubleLu(final byte[] in, final byte[] ret) {
        final int carry = shiftLeft(in, ret);

        /*
         * NOTE: This construction is an attempt at a constant-time implementation.
         */
        final int mask = (-carry) & 0xff;
        ret[in.length - 3] ^= poly[1] & mask;
        ret[in.length - 2] ^= poly[2] & mask;
        ret[in.length - 1] ^= poly[3] & mask;
    }

    private static byte[] lookupPoly(final int blockSizeLength) {
        final int xor;
        switch (blockSizeLength * 8) {
        case 64:
            xor = 0x1B;
            break;
        case 128:
            xor = 0x87;
            break;
        case 160:
            xor = 0x2D;
            break;
        case 192:
            xor = 0x87;
            break;
        case 224:
            xor = 0x309;
            break;
        case 256:
            xor = 0x425;
            break;
        case 320:
            xor = 0x1B;
            break;
        case 384:
            xor = 0x100D;
            break;
        case 448:
            xor = 0x851;
            break;
        case 512:
            xor = 0x125;
            break;
        case 768:
            xor = 0xA0011;
            break;
        case 1024:
            xor = 0x80043;
            break;
        case 2048:
            xor = 0x86001;
            break;
        default:
            throw new IllegalArgumentException("Unknown block size for CMAC: " + (blockSizeLength * 8));
        }

        return Pack.intToBigEndian(xor);
    }

    @Override
    public void init(final Key key) {
        this.prevKey = key;
        reset();

        initLu();
    }

    private void initLu() {
        //initializes the L, Lu, Lu2 numbers
        cipher.update(zeroes, 0, zeroes.length, l, 0);
        doubleLu(l, lu1);
        doubleLu(lu1, lu2);
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public void update(final byte in) {
        if (bufOff == buf.capacity()) {
            cipher.update(buf, mac);
            bufOff = 0;
        }

        buf.putByte(bufOff++, in);
    }

    @Override
    public void update(final byte[] input) {
        update(input, 0, input.length);
    }

    @Override
    public void update(final byte[] in, final int pInOff, final int pLen) {
        int inOff = pInOff;
        int len = pLen;
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        final int gapLen = blockSize - bufOff;

        if (len > gapLen) {
            buf.putBytes(bufOff, in, inOff, gapLen);

            cipher.update(buf, mac);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize) {
                cipher.update(in, inOff, blockSize, mac.asByteArray(), 0);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        if (len > 0) {
            buf.putBytes(bufOff, in, inOff, len);
            bufOff += len;
        }
    }

    @Override
    public void update(final IByteBuffer input) {
        int inOff = 0;
        int len = input.capacity();
        if (len < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        final int gapLen = blockSize - bufOff;

        if (len > gapLen) {
            buf.putBytes(bufOff, input, inOff, gapLen);

            cipher.update(buf, mac);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            while (len > blockSize) {
                cipher.update(input.slice(inOff, blockSize), mac);

                len -= blockSize;
                inOff += blockSize;
            }
        }

        if (len > 0) {
            buf.putBytes(bufOff, input, inOff, len);
            bufOff += len;
        }

    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        final int finalPosition = input.limit();
        update(ByteBuffers.wrap(input));
        ByteBuffers.position(input, finalPosition);
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        update(input);
        return doFinal();
    }

    @Override
    public byte[] doFinal() {
        final byte[] hash = new byte[hashSize];
        doFinal(hash, 0);
        return hash;
    }

    @Override
    public int doFinal(final byte[] out, final int outOff) {
        ivBlock.getBytes(0, out, outOff, cipherIV.getIvSize());
        final int macIndex = outOff + cipherIV.getIvSize();
        doFinalInternal(out, macIndex);
        return hashSize;
    }

    private int doFinalInternal(final byte[] out, final int outOff) {
        final byte[] lu;
        if (bufOff == blockSize) {
            lu = lu1;
        } else {
            PADDING.addPadding(buf.asByteArray(), bufOff);
            lu = lu2;
        }

        for (int i = 0; i < mac.capacity(); i++) {
            final byte b = (byte) (buf.getByte(i) ^ lu[i]);
            buf.putByte(i, b);
        }

        cipher.update(buf, mac);

        mac.getBytes(0, out, outOff, blockSize);

        return blockSize;
    }

    @Override
    public void reset() {
        cipherIV.putIV(ivBlock, iv);
        cipher.init(Cipher.ENCRYPT_MODE, prevKey, cipherIV.wrapParam(iv));

        clean();
    }

    private void clean() {
        buf.clear(Bytes.ZERO);
        bufOff = 0;
        Arrays.fill(l, Bytes.ZERO);
        Arrays.fill(lu1, Bytes.ZERO);
        Arrays.fill(lu2, Bytes.ZERO);
    }

    @Override
    public void close() {
        prevKey = null;
        cipher.close();
        clean();
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        return verify(ByteBuffers.wrap(input), ByteBuffers.wrap(signature));
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        cipherIV.getIV(signature, iv);
        cipher.init(Cipher.ENCRYPT_MODE, prevKey, cipherIV.wrapParam(iv));
        clean();
        initLu();
        update(input);
        final byte[] calculatedSignature;
        try {
            calculatedSignature = doFinal();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        final int macIndex = cipherIV.getIvSize();
        return ByteBuffers.constantTimeEquals(signature.sliceFrom(macIndex), calculatedSignature);
    }

}