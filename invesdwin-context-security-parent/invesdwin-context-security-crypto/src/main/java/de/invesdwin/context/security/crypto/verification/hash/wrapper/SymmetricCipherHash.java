package de.invesdwin.context.security.crypto.verification.hash.wrapper;

import javax.annotation.concurrent.NotThreadSafe;

import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.util.Pack;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricCipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.IHashKey;
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

    private final ICipher cipher;
    private final MutableIvParameterSpec iv;
    private final IByteBuffer ivBlock;
    private final ICipherIV cipherIV;
    private IKey prevKey;
    private IKey prevSymmetricKey;
    private Data data;

    public SymmetricCipherHash(final ICipher cipher, final ICipherIV cipherIV) {
        this.cipher = cipher;

        this.iv = new MutableIvParameterSpec(ByteBuffers.allocateByteArray(cipherIV.getAlgorithm().getIvSize()));
        this.ivBlock = ByteBuffers.allocate(cipherIV.getIvBlockSize());
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
    public void init(final HashMode mode, final IKey key) {
        if (key != prevKey) {
            this.prevKey = key;
            final IHashKey cKey = (IHashKey) key;
            this.prevSymmetricKey = new SymmetricCipherKey(cipherIV.getAlgorithm(), cKey.getKey(mode), cipherIV);
        }
        reset();
    }

    @Override
    public boolean isDynamicHashSize() {
        return false;
    }

    @Override
    public int getHashSize() {
        return data.hashSize;
    }

    @Override
    public void update(final byte in) {
        data.update(in);
    }

    @Override
    public void update(final byte[] input) {
        update(input, 0, input.length);
    }

    @Override
    public void update(final byte[] in, final int pInOff, final int pLen) {
        data.update(in, pInOff, pLen);
    }

    @Override
    public void update(final IByteBuffer input) {
        data.update(input);
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        final int finalPosition = input.limit();
        update(ByteBuffers.wrapRelative(input));
        ByteBuffers.position(input, finalPosition);
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        update(input);
        return doFinal();
    }

    @Override
    public byte[] doFinal() {
        final byte[] hash = new byte[data.hashSize];
        doFinal(hash, 0);
        return hash;
    }

    @Override
    public int doFinal(final byte[] out, final int outOff) {
        ivBlock.getBytes(0, out, outOff, cipherIV.getIvBlockSize());
        final int macIndex = outOff + cipherIV.getIvBlockSize();
        data.doFinal(out, macIndex);
        return data.hashSize;
    }

    @SuppressWarnings("deprecation")
    @Override
    public void reset() {
        cipherIV.putIV(ivBlock, iv);
        cipher.init(CipherMode.Encrypt, prevSymmetricKey, cipherIV.wrapParam(iv));
        final int blockSize = cipher.getBlockSize();
        if (data == null || data.blockSize != blockSize) {
            data = new Data(cipher, blockSize, cipherIV.getIvBlockSize());
        }
        data.init();
    }

    @Override
    public void close() {
        prevKey = null;
        prevSymmetricKey = null;
        cipher.close();
        data = null;
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        return verify(ByteBuffers.wrap(input), ByteBuffers.wrap(signature));
    }

    @SuppressWarnings("deprecation")
    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        cipherIV.getIV(signature, iv);
        cipher.init(CipherMode.Encrypt, prevSymmetricKey, cipherIV.wrapParam(iv));
        data.init();
        update(input);
        final byte[] calculatedSignature;
        try {
            calculatedSignature = doFinal();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        final int macIndex = cipherIV.getIvBlockSize();
        return ByteBuffers.constantTimeEquals(signature.sliceFrom(macIndex), calculatedSignature, macIndex,
                signature.remaining(macIndex));
    }

    private static final class Data {
        private final ICipher cipher;

        private final byte[] poly;
        private final byte[] zeroes;

        private final IByteBuffer mac;
        private final IByteBuffer buf;
        private int bufOff;

        private final int blockSize;
        private final int hashSize;

        private final byte[] l, lu1, lu2;

        private Data(final ICipher cipher, final int blockSize, final int ivSize) {
            this.cipher = cipher;
            this.hashSize = cipher.getBlockSize() + cipher.getHashSize() + ivSize;
            this.blockSize = cipher.getBlockSize();
            this.poly = lookupPoly(blockSize);

            this.mac = ByteBuffers.allocate(blockSize);
            this.buf = ByteBuffers.allocate(blockSize);
            this.zeroes = new byte[blockSize];
            this.bufOff = 0;

            this.l = new byte[blockSize];
            this.lu1 = new byte[blockSize];
            this.lu2 = new byte[blockSize];
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

        private void init() {
            buf.clear();
            bufOff = 0;

            //initializes the L, Lu, Lu2 numbers
            cipher.update(zeroes, 0, zeroes.length, l, 0);
            doubleLu(l, lu1);
            doubleLu(lu1, lu2);
        }

        private void update(final byte in) {
            if (bufOff == buf.capacity()) {
                cipher.update(buf, mac);
                bufOff = 0;
            }

            buf.putByte(bufOff++, in);
        }

        private void update(final byte[] in, final int pInOff, final int pLen) {
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

        private void update(final IByteBuffer input) {
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

        private int doFinal(final byte[] out, final int outOff) {
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

            cipher.doFinal(buf, mac);

            mac.getBytes(0, out, outOff, blockSize);

            init();

            return blockSize;
        }

    }

}