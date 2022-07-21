package de.invesdwin.context.security.crypto.key.password.argon2.jvm.parallel.base;

import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.annotation.concurrent.Immutable;

import com.password4j.SecureString;

// CHECKSTYLE:OFF
@Immutable
class Utils {

    static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final char[] HEX_ALPHABET = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
            'e', 'f' };

    private static final char[] TO_BASE64 = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
            'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
            '5', '6', '7', '8', '9', '+', '/' };

    private static final int[] FROM_BASE64 = new int[256];

    static {
        Arrays.fill(FROM_BASE64, -1);
        for (int i = 0; i < TO_BASE64.length; i++) {
            FROM_BASE64[TO_BASE64[i]] = i;
        }
        FROM_BASE64['='] = -2;
    }

    private Utils() {
        //
    }

    static byte[] fromCharSequenceToBytes(final CharSequence charSequence) {
        if (charSequence == null) {
            return new byte[0];
        }
        final CharsetEncoder encoder = DEFAULT_CHARSET.newEncoder();
        final int length = charSequence.length();
        final int arraySize = scale(length, encoder.maxBytesPerChar());
        final byte[] result = new byte[arraySize];
        if (length == 0) {
            return result;
        } else {
            char[] charArray;
            if (charSequence instanceof String) {
                charArray = ((String) charSequence).toCharArray();
            } else {
                charArray = fromCharSequenceToChars(charSequence);
            }

            charArray = Arrays.copyOfRange(charArray, 0, length);

            encoder.onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .reset();

            final java.nio.ByteBuffer byteBuffer = java.nio.ByteBuffer.wrap(result);
            final CharBuffer charBuffer = CharBuffer.wrap(charArray, 0, length);

            encoder.encode(charBuffer, byteBuffer, true);
            encoder.flush(byteBuffer);

            return Arrays.copyOf(result, byteBuffer.position());
        }

    }

    static char[] fromCharSequenceToChars(final CharSequence charSequence) {
        if (charSequence == null || charSequence.length() == 0) {
            return new char[0];
        }
        final char[] result = new char[charSequence.length()];
        for (int i = 0; i < charSequence.length(); i++) {
            result[i] = charSequence.charAt(i);
        }

        return result;
    }

    static CharSequence append(final CharSequence cs1, final CharSequence cs2) {
        if (cs1 == null || cs1.length() == 0) {
            return cs2;
        }

        if (cs2 == null || cs2.length() == 0) {
            return cs1;
        }

        final char[] charArray1 = fromCharSequenceToChars(cs1);
        final char[] charArray2 = fromCharSequenceToChars(cs2);

        final char[] result = new char[charArray1.length + charArray2.length];
        System.arraycopy(charArray1, 0, result, 0, charArray1.length);
        System.arraycopy(charArray2, 0, result, charArray1.length, charArray2.length);

        return new SecureString(result);

    }

    static String toHex(final byte[] bytes) {
        final int length = bytes.length;
        final char[] output = new char[length << 1];
        int j = 0;
        for (final byte aByte : bytes) {
            output[j++] = HEX_ALPHABET[(0xF0 & aByte) >>> 4];
            output[j++] = HEX_ALPHABET[0x0F & aByte];
        }
        return new String(output);
    }

    static long littleEndianToLong(final byte[] bs, final int off) {
        final int lo = littleEndianToInt(bs, off);
        final int hi = littleEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }

    static int littleEndianToInt(final byte[] bs, int off) {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    static byte[] longToLittleEndian(final long n) {
        final byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    static void longToLittleEndian(final long n, final byte[] bs, final int off) {
        intToLittleEndian((int) (n & 0xffffffffL), bs, off);
        intToLittleEndian((int) (n >>> 32), bs, off + 4);
    }

    static void intToLittleEndian(final int n, final byte[] bs, int off) {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 24);
    }

    static byte[] intToLittleEndianBytes(final int a) {
        final byte[] result = new byte[4];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        return result;
    }

    static long[] fromBytesToLongs(final byte[] input) {
        final long[] v = new long[128];
        for (int i = 0; i < v.length; i++) {
            final byte[] slice = Arrays.copyOfRange(input, i * 8, (i + 1) * 8);
            v[i] = littleEndianBytesToLong(slice);
        }
        return v;
    }

    static String fromBytesToString(final byte[] input) {
        return new String(input, DEFAULT_CHARSET);
    }

    static long littleEndianBytesToLong(final byte[] b) {
        long result = 0;
        for (int i = 7; i >= 0; i--) {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

    static byte[] longToLittleEndianBytes(final long a) {
        final byte[] result = new byte[8];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        result[4] = (byte) ((a >> 32) & 0xFF);
        result[5] = (byte) ((a >> 40) & 0xFF);
        result[6] = (byte) ((a >> 48) & 0xFF);
        result[7] = (byte) ((a >> 56) & 0xFF);
        return result;
    }

    static long intToLong(final int x) {
        final byte[] intBytes = intToLittleEndianBytes(x);
        final byte[] bytes = new byte[8];
        System.arraycopy(intBytes, 0, bytes, 0, 4);
        return littleEndianBytesToLong(bytes);
    }

    static void xor(final long[] t, final long[] b1, final long[] b2) {
        for (int i = 0; i < t.length; i++) {
            t[i] = b1[i] ^ b2[i];
        }
    }

    static void xor(final long[] t, final long[] b1, final long[] b2, final long[] b3) {
        for (int i = 0; i < t.length; i++) {
            t[i] = b1[i] ^ b2[i] ^ b3[i];
        }
    }

    static void xor(final long[] t, final long[] other) {
        for (int i = 0; i < t.length; i++) {
            t[i] = t[i] ^ other[i];
        }
    }

    static int log2(int number) {
        int log = 0;
        if ((number & -65536) != 0) {
            number >>>= 16;
            log = 16;
        }
        if (number >= 256) {
            number >>>= 8;
            log += 8;
        }
        if (number >= 16) {
            number >>>= 4;
            log += 4;
        }
        if (number >= 4) {
            number >>>= 2;
            log += 2;
        }
        return log + (number >>> 1);
    }

    private static int scale(final int initialLength, final float bytesPerChar) {
        return (int) ((double) initialLength * (double) bytesPerChar);
    }

    static byte[] decodeBase64(final String src) {
        return decodeBase64(src.getBytes(StandardCharsets.ISO_8859_1));
    }

    static String encodeBase64(final byte[] src) {
        return encodeBase64(src, true);
    }

    static String encodeBase64(final byte[] src, final boolean padding) {
        final byte[] encoded = encode(src, padding);
        return new String(encoded, 0, encoded.length);
    }

    static byte[] decodeBase64(final byte[] src) {
        byte[] dst = new byte[outLength(src, src.length)];
        final int ret = decode(src, src.length, dst);
        if (ret != dst.length) {
            dst = Arrays.copyOf(dst, ret);
        }
        return dst;
    }

    static byte[] encode(final byte[] src, final boolean padding) {
        final int len = outLength(src.length, padding);
        final byte[] dst = new byte[len];
        final int ret = encode(src, src.length, dst, padding);
        if (ret != dst.length) {
            return Arrays.copyOf(dst, ret);
        }
        return dst;
    }

    private static int outLength(final int length, final boolean doPadding) {
        int len;
        if (doPadding) {
            len = 4 * ((length + 2) / 3);
        } else {
            final int n = length % 3;
            len = 4 * (length / 3) + (n == 0 ? 0 : n + 1);
        }
        return len;
    }

    private static int outLength(final byte[] source, final int length) {
        int paddings = 0;
        if (length == 0) {
            return 0;
        }
        if (length < 2) {
            throw new IllegalArgumentException("Input byte[] should at least have 2 bytes for base64 bytes");
        }

        if (source[length - 1] == '=') {
            paddings++;
            if (source[length - 2] == '=') {
                paddings++;
            }
        }

        if (paddings == 0 && (length & 0x3) != 0) {
            paddings = 4 - (length & 0x3);
        }
        return 3 * ((length + 3) / 4) - paddings;
    }

    private static int encode(final byte[] src, final int end, final byte[] dst, final boolean padding) {
        final char[] base64 = TO_BASE64;
        int sp = 0;
        final int length = (end) / 3 * 3;
        int dp = 0;
        while (sp < length) {
            final int sl0 = sp + length;
            for (int sp0 = sp, dp0 = dp; sp0 < sl0; sp0 += 3, dp0 += 4) {
                final int bits = (src[sp0] & 0xff) << 16 | (src[sp0 + 1] & 0xff) << 8 | (src[sp0 + 2] & 0xff);
                dst[dp0] = (byte) base64[(bits >>> 18) & 0x3f];
                dst[dp0 + 1] = (byte) base64[(bits >>> 12) & 0x3f];
                dst[dp0 + 2] = (byte) base64[(bits >>> 6) & 0x3f];
                dst[dp0 + 3] = (byte) base64[bits & 0x3f];
            }
            final int dlen = (sl0 - sp) / 3 * 4;
            dp += dlen;
            sp = sl0;
        }
        if (sp < end) {
            final int b0 = src[sp++] & 0xff;
            dst[dp++] = (byte) base64[b0 >> 2];
            if (sp == end) {
                dst[dp++] = (byte) base64[(b0 << 4) & 0x3f];
                if (padding) {
                    dst[dp++] = '=';
                    dst[dp++] = '=';
                }
            } else {
                final int b1 = src[sp] & 0xff;
                dst[dp++] = (byte) base64[(b0 << 4) & 0x3f | (b1 >> 4)];
                dst[dp++] = (byte) base64[(b1 << 2) & 0x3f];
                if (padding) {
                    dst[dp++] = '=';
                }
            }
        }
        return dp;
    }

    private static int decode(final byte[] src, final int sl, final byte[] dst) {
        int dp = 0;
        int bits = 0;
        int sp = 0;
        int shiftTo = 18;
        while (sp < sl) {
            int b = src[sp++] & 0xff;
            if ((b = FROM_BASE64[b]) < 0) {
                if (b == -2) {
                    if (shiftTo == 6 && (sp == sl || src[sp] != '=') || shiftTo == 18) {
                        throw new IllegalArgumentException("Input byte array has wrong 4-byte ending unit");
                    }
                    break;
                } else {
                    throw new IllegalArgumentException("Illegal base64 character " + Integer.toString(src[sp - 1], 16));
                }
            }
            bits |= (b << shiftTo);
            shiftTo -= 6;
            if (shiftTo < 0) {
                dst[dp++] = (byte) (bits >> 16);
                dst[dp++] = (byte) (bits >> 8);
                dst[dp++] = (byte) (bits);
                shiftTo = 18;
                bits = 0;
            }
        }
        if (shiftTo == 6) {
            dst[dp++] = (byte) (bits >> 16);
        } else if (shiftTo == 0) {
            dst[dp++] = (byte) (bits >> 16);
            dst[dp++] = (byte) (bits >> 8);
        } else if (shiftTo == 12) {
            throw new IllegalArgumentException("Last unit does not have enough valid bits");
        }
        return dp;
    }

}
