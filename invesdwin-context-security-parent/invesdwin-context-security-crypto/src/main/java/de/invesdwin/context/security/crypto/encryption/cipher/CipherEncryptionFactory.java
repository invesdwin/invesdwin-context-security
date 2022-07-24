package de.invesdwin.context.security.crypto.encryption.cipher;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.encryption.EncryptingDelegateSerde;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.ICipherIV;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.ALazyDelegateInputStream;
import de.invesdwin.util.streams.ALazyDelegateOutputStream;
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
@Immutable
public class CipherEncryptionFactory implements IEncryptionFactory {

    private final ICipherAlgorithm algorithm;
    private final byte[] key;
    private final Key keyWrapped;
    private final ICipherIV cipherIV;

    public CipherEncryptionFactory(final byte[] derivedKey, final byte[] derivedIV) {
        this(ICipherAlgorithm.DEFAULT, derivedKey, new CipherDerivedIV(ICipherAlgorithm.DEFAULT, derivedIV));
    }

    public CipherEncryptionFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(ICipherAlgorithm.DEFAULT, derivedKeyProvider);
    }

    public CipherEncryptionFactory(final ICipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKey("crypto-key".getBytes(), AesKeyLength._256.getBytes()),
                new CipherDerivedIV(algorithm, derivedKeyProvider));
    }

    public CipherEncryptionFactory(final ICipherAlgorithm algorithm, final byte[] key, final ICipherIV cipherIV) {
        this.algorithm = algorithm;
        this.key = key;
        this.keyWrapped = algorithm.wrapKey(key);
        this.cipherIV = cipherIV;
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out) {
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                final byte[] iv = cipherIV.putNewIV(out);
                return algorithm.newEncryptor(out, key, iv);
            }
        };
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final byte[] iv = cipherIV.getNewIV(in);
                return algorithm.newDecryptor(in, key, iv);
            }
        };
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = algorithm.getCipherPool().borrowObject();
        final MutableIvParameterSpec iv = cipherIV.borrowDestIV();
        try {
            cipherIV.putIV(dest, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keyWrapped, algorithm.wrapIv(iv));
            final IByteBuffer payloadBuffer = dest.sliceFrom(Long.BYTES);
            final int length = cipher.doFinal(src, payloadBuffer);
            return cipherIV.getBlockSizeIV() + length;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        } finally {
            cipherIV.returnDestIV(iv);
            algorithm.getCipherPool().returnObject(cipher);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = algorithm.getCipherPool().borrowObject();
        final MutableIvParameterSpec iv = algorithm.getIvParameterSpecPool().borrowObject();
        try {
            cipherIV.getIV(src, iv);
            cipher.init(Cipher.DECRYPT_MODE, keyWrapped, algorithm.wrapIv(iv));
            final IByteBuffer payloadBuffer = src.sliceFrom(Long.BYTES);
            final int length = cipher.doFinal(payloadBuffer, dest);
            return length;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        } finally {
            algorithm.getIvParameterSpecPool().returnObject(iv);
            algorithm.getCipherPool().returnObject(cipher);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde) {
        return new EncryptingDelegateSerde<>(serde, this);
    }

}
