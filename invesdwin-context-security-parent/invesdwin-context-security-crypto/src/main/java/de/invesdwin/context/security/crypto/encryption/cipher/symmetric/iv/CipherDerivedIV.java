package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicLong;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.ContextProperties;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.util.streams.InputStreams;
import de.invesdwin.util.streams.OutputStreams;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Derived IV is the best compromise between security and speed. It does not send the IV over the wire, instead it only
 * sends the counter (sequence number which has half the length of the IV). It expects both sides to use the same key
 * agreement protocol for the derivedIV and counted derivations of it.
 * 
 * Key derivation techniques are: Password+PBKDF2+HKDFexpands or Random+HKDFextract+HKDFexpands
 * 
 * We can derive AES-KEY, AES-IV, MAC-KEY from the initial Password or Random. scrypt and bcrypt are alternatives to
 * PBKDF2
 */
@NotThreadSafe
public class CipherDerivedIV implements ICipherIV {

    private final ISymmetricCipherAlgorithm algorithm;
    private final byte[] initIV;
    private final AtomicLong ivCounter;

    public CipherDerivedIV(final ISymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKey("crypto-iv".getBytes(), algorithm.getIvSize()));
    }

    public CipherDerivedIV(final ISymmetricCipherAlgorithm algorithm, final byte[] derivedIV) {
        this.algorithm = algorithm;
        this.initIV = newInitIV(algorithm.getIvSize());
        this.ivCounter = newIvCounter();
        assert initIV.length == algorithm.getIvSize() : "initIV.length[" + initIV.length + "] != algorithm.getIvBytes["
                + algorithm.getIvSize() + "]";
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getBlockSizeIV() {
        return Long.BYTES;
    }

    protected byte[] newInitIV(final int ivBytes) {
        return newRandomIV(ivBytes);
    }

    protected AtomicLong newIvCounter() {
        return newRandomIvCounter();
    }

    protected void deriveIV(final byte[] initIV, final long pCounter, final byte[] iv) {
        calculateIV(initIV, pCounter, iv);
    }

    @Override
    public int putIV(final IByteBuffer output, final MutableIvParameterSpec destIV) {
        final long counter = ivCounter.incrementAndGet();
        deriveIV(initIV, counter, destIV.getIV());
        output.putLong(0, counter);
        return getBlockSizeIV();
    }

    @Override
    public int putIV(final OutputStream output, final MutableIvParameterSpec destIV) {
        final long counter = ivCounter.incrementAndGet();
        deriveIV(initIV, counter, destIV.getIV());
        try {
            OutputStreams.writeLong(output, counter);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
        return getBlockSizeIV();
    }

    @Override
    public void getIV(final IByteBuffer input, final MutableIvParameterSpec destIV) {
        final long counter = input.getLong(0);
        deriveIV(initIV, counter, destIV.getIV());
    }

    @Override
    public void getIV(final InputStream input, final MutableIvParameterSpec destIV) {
        final long counter;
        try {
            counter = InputStreams.readLong(input);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
        deriveIV(initIV, counter, destIV.getIV());
    }

    public static byte[] newRandomIV(final int ivBytes) {
        final byte[] initIV = ByteBuffers.allocateByteArray(ivBytes);
        randomizeIV(initIV);
        return initIV;
    }

    public static void randomizeIV(final byte[] initIV) {
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            random.nextBytes(initIV);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
    }

    public static AtomicLong newRandomIvCounter() {
        if (ContextProperties.IS_TEST_ENVIRONMENT) {
            //make debugging easier by using 0 counter always during testing
            return new AtomicLong();
        } else {
            final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
            try {
                /*
                 * start at a random counter, so it does not matter when the classes are initialized, the counter will
                 * not be predictably at 0. So that an attacker does not know how long the communication chnanel has
                 * been established.
                 * 
                 * We anyway either send the IV or the counter over the wire so there is no secret in the counter
                 * itself.
                 */
                return new AtomicLong(random.nextLong());
            } finally {
                CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
            }
        }
    }

    public static void calculateIV(final byte[] initIV, final long pCounter, final byte[] iv) {
        long counter = pCounter;
        int i = iv.length; // IV length
        int j = 0; // counter bytes index
        int sum = 0;
        while (i-- > 0) {
            // (sum >>> Byte.SIZE) is the carry for addition
            sum = (initIV[i] & 0xff) + (sum >>> Byte.SIZE); // NOPMD
            if (j++ < 8) { // Big-endian, and long is 8 bytes length
                sum += (byte) counter & 0xff;
                counter >>>= 8;
            }
            iv[i] = (byte) sum;
        }
    }

}
