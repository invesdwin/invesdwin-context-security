package de.invesdwin.context.security.crypto.encryption.cipher.stream;

import java.io.IOException;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherEncryptionFactoryTest;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.key.DerivedKeyProvider;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.context.test.ATest;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import it.unimi.dsi.fastutil.io.FastByteArrayInputStream;
import it.unimi.dsi.fastutil.io.FastByteArrayOutputStream;

@NotThreadSafe
public class StreamingCipherInputStreamTest extends ATest {

    @Test
    public void testEncryptionAndDecryption() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] key = ByteBuffers.allocateByteArray(AesKeyLength._256.getBytes());
            //            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(CipherEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        final byte[] key = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(), AesKeyLength._256.getBytes());
        for (final AesAlgorithm algorithm : AesAlgorithm.values()) {
            final byte[] iv = derivedKeyProvider.newDerivedKey("preshared-iv".getBytes(), algorithm.getIvSize());
            try {
                testEncryptionAndDecryption(algorithm, key, iv, "1234567890", "0987654321");
                testEncryptionAndDecryption(algorithm, key, iv, "0987654321", "1234567890");
            } catch (final IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void testEncryptionAndDecryption(final AesAlgorithm algorithm, final byte[] key, final byte[] iv,
            final String... payloads) throws IOException {
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
