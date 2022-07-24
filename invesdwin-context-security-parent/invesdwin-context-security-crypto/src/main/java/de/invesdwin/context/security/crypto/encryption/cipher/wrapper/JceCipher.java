package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;

@NotThreadSafe
public class JceCipher implements ICipher {

    private final byte[] oneByteBuf = new byte[1];
    private final Cipher cipher;
    private final int signatureSize;

    public JceCipher(final Cipher cipher, final int signatureSize) {
        this.cipher = cipher;
        this.signatureSize = signatureSize;
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    @Override
    public int getSignatureSize() {
        return signatureSize;
    }

    @Override
    public String getAlgorithm() {
        return cipher.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        try {
            cipher.init(mode, key, params);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
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
        try {
            return cipher.update(input, inputOffset, inputLen, output);
        } catch (final ShortBufferException e) {
            throw new RuntimeException(e);
        }
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
        try {
            return cipher.doFinal(input, inputOffset, inputLen, output);
        } catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
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
            return cipher.doFinal(output, offset);
        } catch (IllegalBlockSizeException | ShortBufferException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] doFinal() {
        try {
            return cipher.doFinal();
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void updateAAD(final byte aad) {
        oneByteBuf[0] = aad;
        cipher.updateAAD(oneByteBuf);
    }

    @Override
    public void updateAAD(final byte[] aad) {
        cipher.updateAAD(aad);
    }

    @Override
    public void updateAAD(final byte[] aad, final int inputOffset, final int inputLen) {
        cipher.updateAAD(aad, inputOffset, inputLen);
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer aad) {
        cipher.updateAAD(aad);
    }

    @Override
    public void close() {
    }

}
