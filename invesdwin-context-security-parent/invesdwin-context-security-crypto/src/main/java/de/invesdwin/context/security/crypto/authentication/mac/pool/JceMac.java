package de.invesdwin.context.security.crypto.authentication.mac.pool;

import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.NotThreadSafe;
import javax.crypto.Mac;

@NotThreadSafe
public class JceMac implements IMac {

    private final Mac mac;
    private boolean needsReset;
    private int prevKeyIdentity;

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
        final int keyIdentity = System.identityHashCode(key);
        if (prevKeyIdentity == keyIdentity) {
            //init not needed if it is the same key
            reset(); //checks itself if reset is needed
            return;
        }
        try {
            mac.init(key);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        prevKeyIdentity = keyIdentity;
        needsReset = false;
    }

    @Override
    public void update(final byte input) {
        needsReset = true;
        mac.update(input);
        needsReset = true;
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        needsReset = true;
        mac.update(input);
    }

    @Override
    public void update(final byte[] input) {
        needsReset = true;
        mac.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        needsReset = true;
        mac.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        final byte[] result = mac.doFinal();
        needsReset = false;
        return result;
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        final byte[] result = mac.doFinal(input);
        needsReset = false;
        return result;
    }

    @Override
    public void doFinal(final byte[] output, final int offset) {
        try {
            mac.doFinal(output, offset);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        needsReset = false;
    }

    @Override
    public void reset() {
        if (needsReset) {
            mac.reset();
        }
        needsReset = false;
    }

}
