package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.util.lang.Closeables;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class CryptoCipher implements ICipher {

    private final org.apache.commons.crypto.cipher.CryptoCipher cipher;

    public CryptoCipher(final org.apache.commons.crypto.cipher.CryptoCipher cipher) {
        this.cipher = cipher;
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    @Override
    public String getAlgorithm() {
        return cipher.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        try {
            cipher.init(mode, key, params);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int update(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        try {
            return cipher.update(inBuffer.asNioByteBuffer(), outBuffer.asNioByteBuffer());
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
    public int doFinal(final IByteBuffer inBuffer, final IByteBuffer outBuffer) {
        try {
            return cipher.doFinal(inBuffer.asNioByteBuffer(), outBuffer.asNioByteBuffer());
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
            return cipher.doFinal(null, 0, 0, output, offset);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] doFinal() {
        final IByteBuffer buffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
        try {
            buffer.ensureCapacity(getBlockSize());
            final int written;
            try {
                written = cipher.doFinal(null, buffer.asNioByteBuffer());
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
            assert written == getBlockSize() : "written [" + written + "] != blockSize [" + getBlockSize() + "]";
            return buffer.asByteArrayCopy(0, written);
        } finally {
            ByteBuffers.EXPANDABLE_POOL.returnObject(buffer);
        }
    }

    @Override
    public void updateAAD(final byte[] aad) {
        cipher.updateAAD(aad);
    }

    @Override
    public void updateAAD(final byte[] aad, final int inputOffset, final int inputLen) {
        cipher.updateAAD(ByteBuffers.wrap(aad, inputOffset, inputLen).asNioByteBuffer());
    }

    @Override
    public void updateAAD(final IByteBuffer aad) {
        cipher.updateAAD(aad.asNioByteBuffer());
    }

    @Override
    public void close() {
        Closeables.closeQuietly(cipher);
    }

}
