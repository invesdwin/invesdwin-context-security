package de.invesdwin.context.security.crypto.authentication.mac.wrapper;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class JceMac implements IMac {

    private final Mac mac;

    public JceMac(final String algorithm) {
        this(getJceMacInstance(algorithm));
    }

    public JceMac(final Mac mac) {
        this.mac = mac;
    }

    public static Mac getJceMacInstance(final String algorithm) {
        try {
            return Mac.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return mac.getAlgorithm();
    }

    @Override
    public int getMacLength() {
        return mac.getMacLength();
    }

    @Override
    public void init(final Key key) {
        try {
            mac.init(key);
        } catch (final InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void update(final byte input) {
        mac.update(input);
    }

    @Override
    public void update(final IByteBuffer input) {
        mac.update(input.asNioByteBuffer());
    }

    @Override
    public void update(final byte[] input) {
        mac.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        mac.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        return mac.doFinal();
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        return mac.doFinal(input);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        try {
            mac.doFinal(output, offset);
            return getMacLength();
        } catch (ShortBufferException | IllegalStateException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset() {
        mac.reset();
    }

    @Override
    public void close() {
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        update(input);
        final byte[] calculatedSignature = doFinal();
        return ByteBuffers.constantTimeEquals(signature, calculatedSignature);
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        update(input);
        final byte[] calculatedSignature = doFinal();
        return ByteBuffers.constantTimeEquals(signature, calculatedSignature);
    }

}
