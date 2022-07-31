package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric;

import java.io.IOException;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaKeySize;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.AsymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.AsymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.StreamingAsymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.stream.StreamingAsymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeySize;
import de.invesdwin.context.security.crypto.key.DerivedKeyProvider;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.context.test.ATest;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import it.unimi.dsi.fastutil.io.FastByteArrayInputStream;
import it.unimi.dsi.fastutil.io.FastByteArrayOutputStream;

@NotThreadSafe
public class AsymmetricEncryptionFactoryTest extends ATest {

    @Test
    public void testEncryptionAndDecryption() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] key = ByteBuffers.allocateByteArray(AesKeySize.DEFAULT.getBytes());
            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(AsymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        for (final RsaAlgorithm algorithm : RsaAlgorithm.values()) {
            final AsymmetricCipherKey key = new AsymmetricCipherKey(algorithm, derivedKeyProvider);
            final AsymmetricEncryptionFactory factory = new AsymmetricEncryptionFactory(key);
            testEncryptionAndDecryption(factory, "1234567890");
            testEncryptionAndDecryption(factory, "0987654321");
        }
    }

    private void testEncryptionAndDecryption(final AsymmetricEncryptionFactory factory, final String payload) {
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
            final byte[] key = ByteBuffers.allocateByteArray(AesKeySize.DEFAULT.getBytes());
            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(AsymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        for (final RsaAlgorithm algorithm : RsaAlgorithm.values()) {
            final AsymmetricCipherKey key = new AsymmetricCipherKey(algorithm, derivedKeyProvider);
            try {
                testCipherStream(algorithm, key, "1234567890", "0987654321");
                testCipherStream(algorithm, key, "0987654321", "1234567890");
            } catch (final IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void testCipherStream(final IAsymmetricCipherAlgorithm algorithm, final AsymmetricCipherKey key,
            final String... payloads) throws IOException {
        final FastByteArrayOutputStream encryptedOutputStream = new FastByteArrayOutputStream();
        final AsymmetricCipherOutputStream encryptingStream = new AsymmetricCipherOutputStream(algorithm,
                encryptedOutputStream, key);

        final FastByteArrayInputStream encryptedInputStream = new FastByteArrayInputStream(Bytes.EMPTY_ARRAY);
        final AsymmetricCipherInputStream decryptingStream = new AsymmetricCipherInputStream(algorithm,
                encryptedInputStream, key);

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
            final byte[] key = ByteBuffers.allocateByteArray(RsaKeySize.DEFAULT.getBytes());
            //            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(AsymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        for (final RsaAlgorithm algorithm : RsaAlgorithm.values()) {
            final AsymmetricCipherKey key = new AsymmetricCipherKey(algorithm, derivedKeyProvider);
            try {
                testStreamingCipherStream(algorithm, key, "1234567890", "0987654321");
                testStreamingCipherStream(algorithm, key, "0987654321", "1234567890");
            } catch (final IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void testStreamingCipherStream(final IAsymmetricCipherAlgorithm algorithm, final AsymmetricCipherKey key,
            final String... payloads) throws IOException {
        final FastByteArrayOutputStream encryptedOutputStream = new FastByteArrayOutputStream();
        final StreamingAsymmetricCipherOutputStream encryptingStream = new StreamingAsymmetricCipherOutputStream(
                algorithm, encryptedOutputStream, key);

        final FastByteArrayInputStream encryptedInputStream = new FastByteArrayInputStream(Bytes.EMPTY_ARRAY);
        final StreamingAsymmetricCipherInputStream decryptingStream = new StreamingAsymmetricCipherInputStream(
                algorithm, encryptedInputStream, key);

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
