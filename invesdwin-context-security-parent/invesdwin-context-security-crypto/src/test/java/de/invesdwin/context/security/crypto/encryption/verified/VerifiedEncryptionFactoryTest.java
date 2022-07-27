package de.invesdwin.context.security.crypto.encryption.verified;

import java.io.IOException;
import java.util.Arrays;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import de.invesdwin.context.security.crypto.encryption.cipher.SymmetricEncryptionFactoryTest;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherPresharedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherRandomIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.CipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.CipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.verified.algorithm.VerifiedSymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.key.DerivedKeyProvider;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.HashVerificationFactory;
import de.invesdwin.context.test.ATest;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import it.unimi.dsi.fastutil.io.FastByteArrayInputStream;
import it.unimi.dsi.fastutil.io.FastByteArrayOutputStream;

@NotThreadSafe
public class VerifiedEncryptionFactoryTest extends ATest {

    @Test
    public void testEncryptionAndDecryption() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] key = ByteBuffers.allocateByteArray(AesKeyLength.DEFAULT.getBytes());
            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(SymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        final byte[] key = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(), AesKeyLength.DEFAULT.getBytes());
        for (final AesAlgorithm algorithm : AesAlgorithm.values()) {
            final CipherDerivedIV derivedIV = new CipherDerivedIV(algorithm, derivedKeyProvider);
            final CipherCountedIV countedIV = new CipherCountedIV(algorithm);
            final CipherPresharedIV presharedIV = new CipherPresharedIV(algorithm,
                    derivedKeyProvider.newDerivedKey("preshared-iv".getBytes(), algorithm.getIvSize()));
            final CipherRandomIV randomIV = new CipherRandomIV(algorithm);
            for (final ICipherIV iv : Arrays.asList(randomIV, derivedIV, countedIV, presharedIV)) {
                final SymmetricEncryptionFactory cipherFactory = new SymmetricEncryptionFactory(algorithm, key, iv);
                final HashVerificationFactory authenticationFactory = new HashVerificationFactory(derivedKeyProvider);
                final VerifiedEncryptionFactory factory = new VerifiedEncryptionFactory(cipherFactory,
                        authenticationFactory);
                testEncryptionAndDecryption(factory, "1234567890");
                testEncryptionAndDecryption(factory, "0987654321");
            }
        }
    }

    private void testEncryptionAndDecryption(final VerifiedEncryptionFactory factory, final String payload) {
        final String srcStr = payload;
        final IByteBuffer src = ByteBuffers.wrap(srcStr.getBytes());
        final IByteBuffer encrypted = ByteBuffers.allocateExpandable();
        final int encryptedSize = factory.encrypt(src, encrypted);
        final IByteBuffer dst = ByteBuffers.allocateExpandable();
        final int decryptedSize = factory.decrypt(encrypted.sliceTo(encryptedSize), dst);
        Assertions.assertThat(decryptedSize).isEqualTo(src.capacity());
        Assertions.assertThat(ByteBuffers.equals(src, dst.sliceTo(decryptedSize))).isTrue();
    }

    @Test
    public void testCipherStream() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] key = ByteBuffers.allocateByteArray(AesKeyLength.DEFAULT.getBytes());
            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(SymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        final byte[] key = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(), AesKeyLength.DEFAULT.getBytes());
        for (final AesAlgorithm algorithm : AesAlgorithm.values()) {
            final byte[] iv = derivedKeyProvider.newDerivedKey("preshared-iv".getBytes(), algorithm.getIvSize());
            final SymmetricEncryptionFactory cipherFactory = new SymmetricEncryptionFactory(algorithm, key,
                    new CipherPresharedIV(algorithm, iv));
            final HashVerificationFactory verificationFactory = new HashVerificationFactory(derivedKeyProvider);
            final VerifiedEncryptionFactory factory = new VerifiedEncryptionFactory(cipherFactory, verificationFactory);
            try {
                final VerifiedSymmetricCipherAlgorithm verifiedAlgorithm = (VerifiedSymmetricCipherAlgorithm) factory
                        .getAlgorithm();
                testCipherStream(verifiedAlgorithm, key, iv, "1234567890", "0987654321");
                testCipherStream(verifiedAlgorithm, key, iv, "0987654321", "1234567890");
            } catch (final IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void testCipherStream(final VerifiedSymmetricCipherAlgorithm algorithm, final byte[] key, final byte[] iv,
            final String... payloads) throws IOException {
        final FastByteArrayOutputStream encryptedOutputStream = new FastByteArrayOutputStream();
        final CipherOutputStream encryptingStream = new CipherOutputStream(algorithm, encryptedOutputStream, key, iv);

        final FastByteArrayInputStream encryptedInputStream = new FastByteArrayInputStream(Bytes.EMPTY_ARRAY);
        final CipherInputStream decryptingStream = new CipherInputStream(algorithm, encryptedInputStream, key, iv);

        final FastByteArrayOutputStream payloadsOutputStream = new FastByteArrayOutputStream();

        for (final String payload : payloads) {
            encryptedInputStream.reset();

            final byte[] payloadBytes = payload.getBytes();
            encryptingStream.write(payloadBytes);
            encryptingStream.flush();
            payloadsOutputStream.write(payloadBytes);
            payloadsOutputStream.flush();
        }

        encryptingStream.close();

        encryptedInputStream.array = encryptedOutputStream.array;
        encryptedInputStream.length = encryptedOutputStream.length;

        final byte[] decryptedBytes = IOUtils.toByteArray(decryptingStream);
        decryptingStream.close();

        Assertions.assertThat(payloadsOutputStream.length).isEqualTo(decryptedBytes.length);
        Assertions
                .assertThat(ByteBuffers.equals(
                        ByteBuffers.wrapTo(payloadsOutputStream.array, payloadsOutputStream.length), decryptedBytes))
                .isTrue();
        payloadsOutputStream.close();
    }

    @Test
    public void testStreamingCipherStream() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] key = ByteBuffers.allocateByteArray(AesKeyLength.DEFAULT.getBytes());
            //            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(SymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        final byte[] key = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(), AesKeyLength.DEFAULT.getBytes());
        for (final AesAlgorithm algorithm : AesAlgorithm.values()) {
            final byte[] iv = derivedKeyProvider.newDerivedKey("preshared-iv".getBytes(), algorithm.getIvSize());
            final SymmetricEncryptionFactory cipherFactory = new SymmetricEncryptionFactory(algorithm, key,
                    new CipherPresharedIV(algorithm, iv));
            final HashVerificationFactory verificationFactory = new HashVerificationFactory(derivedKeyProvider);
            final VerifiedEncryptionFactory factory = new VerifiedEncryptionFactory(cipherFactory, verificationFactory);
            try {
                final VerifiedSymmetricCipherAlgorithm verifiedAlgorithm = (VerifiedSymmetricCipherAlgorithm) factory
                        .getAlgorithm();
                testStreamingCipherStream(verifiedAlgorithm, key, iv, "1234567890", "0987654321");
                testStreamingCipherStream(verifiedAlgorithm, key, iv, "0987654321", "1234567890");
            } catch (final IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void testStreamingCipherStream(final VerifiedSymmetricCipherAlgorithm algorithm, final byte[] key,
            final byte[] iv, final String... payloads) throws IOException {
        final FastByteArrayOutputStream encryptedOutputStream = new FastByteArrayOutputStream();
        final StreamingCipherOutputStream encryptingStream = new StreamingCipherOutputStream(algorithm,
                encryptedOutputStream, key, iv);

        final FastByteArrayInputStream encryptedInputStream = new FastByteArrayInputStream(Bytes.EMPTY_ARRAY);
        final StreamingCipherInputStream decryptingStream = new StreamingCipherInputStream(algorithm,
                encryptedInputStream, key, iv);

        for (final String payload : payloads) {
            encryptedInputStream.reset();
            encryptedOutputStream.reset();

            final byte[] payloadBytes = payload.getBytes();
            encryptingStream.write(payloadBytes);
            encryptingStream.flush();

            encryptedInputStream.array = encryptedOutputStream.array;
            encryptedInputStream.length = encryptedOutputStream.length;

            final byte[] decryptedBytes = IOUtils.toByteArray(decryptingStream);

            Assertions.assertThat(payloadBytes.length).isEqualTo(decryptedBytes.length);
            Assertions.assertThat(ByteBuffers.equals(payloadBytes, decryptedBytes)).isTrue();
        }

        encryptingStream.close();
        decryptingStream.close();
    }

}
