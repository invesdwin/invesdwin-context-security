package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.apache.commons.crypto.utils.Utils;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherKey;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.system.properties.SystemProperties;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.EmptyByteBuffer;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * commons-crypto does not yet support openssl 3.0.0: https://issues.apache.org/jira/projects/CRYPTO/issues/CRYPTO-164
 *
 * @author subes
 *
 */
@NotThreadSafe
public class CommonsCryptoCipher implements ICipher {

    private final byte[] oneByteBuf = new byte[1];
    private final org.apache.commons.crypto.cipher.CryptoCipher cipher;
    private final int hashSize;

    public CommonsCryptoCipher(final org.apache.commons.crypto.cipher.CryptoCipher cipher, final int hashSize) {
        this.cipher = cipher;
        this.hashSize = hashSize;
    }

    public static org.apache.commons.crypto.cipher.CryptoCipher getCommonsCryptoCipherInstance(final String algorithm) {
        try {
            return Utils.getCipherInstance(algorithm, SystemProperties.SYSTEM_PROPERTIES);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public String getAlgorithm() {
        return cipher.getAlgorithm();
    }

    @Deprecated
    @Override
    public void init(final CipherMode mode, final IKey key, final AlgorithmParameterSpec params) {
        final ICipherKey cKey = (ICipherKey) key;
        try {
            cipher.init(mode.getJceMode(), cKey.getKey(mode), params);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        try {
            return cipher.update(inBuffer, outBuffer);
        } catch (final ShortBufferException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return update(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        try {
            return cipher.update(input, inputOffset, inputLen, output, outputOffset);
        } catch (final ShortBufferException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        try {
            return cipher.doFinal(inBuffer, outBuffer);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return doFinal(input, inputOffset, inputLen, output, 0);
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        try {
            return cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        try {
            return cipher.doFinal(Bytes.EMPTY_ARRAY, 0, 0, output, offset);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] doFinal() {
        final IByteBuffer buffer = ByteBuffers.allocate(getBlockSize());
        final int written;
        try {
            written = cipher.doFinal(EmptyByteBuffer.EMPTY_BYTE_BUFFER, buffer.asNioByteBuffer());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        return buffer.asByteArray(0, written);
    }

    @Override
    public void updateAAD(final byte input) {
        oneByteBuf[0] = input;
        cipher.updateAAD(oneByteBuf);
    }

    @Override
    public void updateAAD(final byte[] input) {
        cipher.updateAAD(input);
    }

    @Override
    public void updateAAD(final byte[] input, final int inputOffset, final int inputLen) {
        cipher.updateAAD(ByteBuffers.wrap(input, inputOffset, inputLen).asNioByteBuffer());
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer input) {
        cipher.updateAAD(input);
    }

    @Override
    public void close() {
        Closeables.closeQuietly(cipher);
    }

}
