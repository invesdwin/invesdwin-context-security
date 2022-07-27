package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.encryption.EncryptionDelegateSerde;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingSymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingSymmetricCipherOutputStream;
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
public class SymmetricEncryptionFactory implements IEncryptionFactory {

    private final ISymmetricCipherAlgorithm algorithm;
    private final byte[] key;
    private final Key keyWrapped;
    private final ICipherIV cipherIV;

    public SymmetricEncryptionFactory(final byte[] derivedKey, final byte[] derivedIV) {
        this(ISymmetricCipherAlgorithm.DEFAULT, derivedKey,
                new CipherDerivedIV(ISymmetricCipherAlgorithm.DEFAULT, derivedIV));
    }

    public SymmetricEncryptionFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(ISymmetricCipherAlgorithm.DEFAULT, derivedKeyProvider);
    }

    public SymmetricEncryptionFactory(final ISymmetricCipherAlgorithm algorithm,
            final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKey("cipher-key".getBytes(), AesKeyLength.DEFAULT.getBytes()),
                new CipherDerivedIV(algorithm, derivedKeyProvider));
    }

    public SymmetricEncryptionFactory(final ISymmetricCipherAlgorithm algorithm, final byte[] key,
            final ICipherIV cipherIV) {
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
    public void init(final ICipher cipher, final int mode, final AlgorithmParameterSpec param) {
        cipher.init(mode, keyWrapped, param);
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out) {
        return newEncryptor(out, algorithm.newCipher());
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher) {
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                final byte[] iv = cipherIV.putNewIV(out);
                try {
                    return new StreamingSymmetricCipherOutputStream(algorithm, out, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        return newDecryptor(in, algorithm.newCipher());
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final byte[] iv = cipherIV.getNewIV(in);
                try {
                    return new StreamingSymmetricCipherInputStream(algorithm, in, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = cipherIV.borrowCipher();
        try {
            return encrypt(src, dest, cipher);
        } finally {
            cipherIV.returnCipher(cipher);
        }
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        final MutableIvParameterSpec iv = cipherIV.borrowDestIV();
        try {
            cipherIV.putIV(dest, iv);
            init(cipher, Cipher.ENCRYPT_MODE, algorithm.wrapParam(iv));
            final IByteBuffer payloadBuffer = dest.sliceFrom(cipherIV.getBlockSizeIV());
            final int length = cipher.doFinal(src, payloadBuffer);
            return cipherIV.getBlockSizeIV() + length;
        } finally {
            cipherIV.returnDestIV(iv);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final ICipher cipher = cipherIV.borrowCipher();
        try {
            return decrypt(src, dest, cipher);
        } finally {
            cipherIV.returnCipher(cipher);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        final MutableIvParameterSpec iv = cipherIV.borrowDestIV();
        try {
            cipherIV.getIV(src, iv);
            init(cipher, Cipher.DECRYPT_MODE, algorithm.wrapParam(iv));
            final IByteBuffer payloadBuffer = src.sliceFrom(cipherIV.getBlockSizeIV());
            final int length = cipher.doFinal(payloadBuffer, dest);
            return length;
        } finally {
            cipherIV.returnDestIV(iv);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde) {
        return new EncryptionDelegateSerde<>(serde, this);
    }

}
