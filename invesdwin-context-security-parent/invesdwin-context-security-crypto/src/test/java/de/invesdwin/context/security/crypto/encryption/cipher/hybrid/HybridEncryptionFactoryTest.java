package de.invesdwin.context.security.crypto.encryption.cipher.hybrid;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricEncryptionFactoryTest;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.RsaKeySize;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricEncryptionFactoryTest;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.algorithm.AesKeySize;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherPresharedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherRandomIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.key.DerivedKeyProvider;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerators;
import de.invesdwin.context.test.ATest;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.collections.Arrays;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;
import it.unimi.dsi.fastutil.io.FastByteArrayInputStream;
import it.unimi.dsi.fastutil.io.FastByteArrayOutputStream;

@NotThreadSafe
public class HybridEncryptionFactoryTest extends ATest {

    @Test
    public void testEncryptionAndDecryption() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        final byte[] key = ByteBuffers.allocateByteArray(AesKeySize.DEFAULT.getBytes());
        random.nextBytes(key);
        derivedKeyProvider = DerivedKeyProvider
                .fromRandom(SymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        for (final ISymmetricCipherAlgorithm symmetricAlgorithm : ISymmetricCipherAlgorithm.values()) {
            final byte[] cipherKey = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(),
                    symmetricAlgorithm.getDefaultKeySizeBits());
            final CipherDerivedIV derivedIV = new CipherDerivedIV(symmetricAlgorithm, derivedKeyProvider);
            final CipherCountedIV countedIV = new CipherCountedIV(symmetricAlgorithm);
            final CipherPresharedIV presharedIV = new CipherPresharedIV(symmetricAlgorithm, derivedKeyProvider
                    .newDerivedKey("preshared-iv".getBytes(), symmetricAlgorithm.getIvSize() * Byte.SIZE));
            final CipherRandomIV randomIV = new CipherRandomIV(symmetricAlgorithm);
            for (final ICipherIV iv : Arrays.asList(randomIV, derivedIV, countedIV, presharedIV)) {
                final SymmetricEncryptionFactory symmetricFactory = new SymmetricEncryptionFactory(symmetricAlgorithm,
                        cipherKey, iv);
                for (final IAsymmetricCipherAlgorithm asymmetricAlgorithm : IAsymmetricCipherAlgorithm.values()) {
                    log.info("%s with %s and %s", asymmetricAlgorithm.getAlgorithm(), symmetricAlgorithm.getAlgorithm(),
                            iv.getClass().getSimpleName());
                    final AsymmetricEncryptionFactory asymmetricFactory = new AsymmetricEncryptionFactory(
                            asymmetricAlgorithm, derivedKeyProvider);
                    for (final HybridEncryptionFactory factory : new HybridEncryptionFactory[] {
                            new HybridEncryptionFactory(asymmetricFactory, symmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, asymmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, symmetricFactory) }) {
                        log.info(" * %s", factory.getAlgorithm().getAlgorithm());
                        testEncryptionAndDecryption(factory, "1234567890");
                        testEncryptionAndDecryption(factory, "0987654321");
                    }
                }
            }
        }
    }

    private void testEncryptionAndDecryption(final HybridEncryptionFactory factory, final String payload) {
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
    public void testCipher() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        final byte[] key = ByteBuffers.allocateByteArray(RsaKeySize.DEFAULT.getBytes());
        random.nextBytes(key);
        derivedKeyProvider = DerivedKeyProvider
                .fromRandom(AsymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        final byte[] cipherKey = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(),
                AesKeySize.DEFAULT.getBits());
        for (final ISymmetricCipherAlgorithm symmetricAlgorithm : ISymmetricCipherAlgorithm.values()) {
            final CipherDerivedIV derivedIV = new CipherDerivedIV(symmetricAlgorithm, derivedKeyProvider);
            final CipherCountedIV countedIV = new CipherCountedIV(symmetricAlgorithm);
            final CipherPresharedIV presharedIV = new CipherPresharedIV(symmetricAlgorithm, derivedKeyProvider
                    .newDerivedKey("preshared-iv".getBytes(), symmetricAlgorithm.getIvSize() * Byte.SIZE));
            final CipherRandomIV randomIV = new CipherRandomIV(symmetricAlgorithm);
            for (final ICipherIV iv : Arrays.asList(randomIV, derivedIV, countedIV, presharedIV)) {
                final SymmetricEncryptionFactory symmetricFactory = new SymmetricEncryptionFactory(symmetricAlgorithm,
                        cipherKey, iv);
                for (final IAsymmetricCipherAlgorithm asymmetricAlgorithm : IAsymmetricCipherAlgorithm.values()) {
                    log.info("%s with %s and %s", asymmetricAlgorithm.getAlgorithm(), symmetricAlgorithm.getAlgorithm(),
                            iv.getClass().getSimpleName());
                    final AsymmetricEncryptionFactory asymmetricFactory = new AsymmetricEncryptionFactory(
                            asymmetricAlgorithm, derivedKeyProvider);
                    for (final HybridEncryptionFactory factory : new HybridEncryptionFactory[] {
                            new HybridEncryptionFactory(asymmetricFactory, symmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, asymmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, symmetricFactory) }) {
                        log.info(" * %s", factory.getAlgorithm().getAlgorithm());
                        testCipher(factory, "1234567890", "0987654321");
                        testCipher(factory, "0987654321", "1234567890");
                    }
                }
            }
        }
    }

    private void testCipher(final HybridEncryptionFactory factory, final String... payloads) {
        for (final String payload : payloads) {
            final ICipher cipher = factory.getCipherPool().borrowObject();
            try {
                final String srcStr = payload;
                final IByteBuffer src = ByteBuffers.wrap(srcStr.getBytes());
                final IByteBuffer encrypted = ByteBuffers.allocateExpandable();
                final int paramsLength = factory.init(CipherMode.Encrypt, cipher, factory.getKey(), encrypted);
                final int encryptedSize = cipher.doFinal(src, encrypted.sliceFrom(paramsLength));
                final IByteBuffer dst = ByteBuffers.allocateExpandable();
                final int paramsLength2 = factory.init(CipherMode.Decrypt, cipher, factory.getKey(), encrypted);
                Assertions.assertThat(paramsLength2).isEqualTo(paramsLength);
                final int decryptedSize = cipher.doFinal(encrypted.slice(paramsLength, encryptedSize), dst);
                Assertions.assertThat(decryptedSize).isEqualTo(src.capacity());
                Assertions.assertThat(ByteBuffers.equals(src, dst.sliceTo(decryptedSize))).isTrue();
            } finally {
                factory.getCipherPool().returnObject(cipher);
            }
        }
    }

    @Test
    public void testCipherStream() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        final byte[] key = ByteBuffers.allocateByteArray(AesKeySize.DEFAULT.getBytes());
        random.nextBytes(key);
        derivedKeyProvider = DerivedKeyProvider
                .fromRandom(SymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        for (final ISymmetricCipherAlgorithm symmetricAlgorithm : ISymmetricCipherAlgorithm.values()) {
            final byte[] cipherKey = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(),
                    symmetricAlgorithm.getDefaultKeySizeBits());
            final CipherDerivedIV derivedIV = new CipherDerivedIV(symmetricAlgorithm, derivedKeyProvider);
            final CipherCountedIV countedIV = new CipherCountedIV(symmetricAlgorithm);
            final CipherPresharedIV presharedIV = new CipherPresharedIV(symmetricAlgorithm, derivedKeyProvider
                    .newDerivedKey("preshared-iv".getBytes(), symmetricAlgorithm.getIvSize() * Byte.SIZE));
            final CipherRandomIV randomIV = new CipherRandomIV(symmetricAlgorithm);
            for (final ICipherIV iv : Arrays.asList(randomIV, derivedIV, countedIV, presharedIV)) {
                final SymmetricEncryptionFactory symmetricFactory = new SymmetricEncryptionFactory(symmetricAlgorithm,
                        cipherKey, iv);
                for (final IAsymmetricCipherAlgorithm asymmetricAlgorithm : IAsymmetricCipherAlgorithm.values()) {
                    log.info("%s with %s and %s", asymmetricAlgorithm.getAlgorithm(), symmetricAlgorithm.getAlgorithm(),
                            iv.getClass().getSimpleName());
                    final AsymmetricEncryptionFactory asymmetricFactory = new AsymmetricEncryptionFactory(
                            asymmetricAlgorithm, derivedKeyProvider);
                    for (final HybridEncryptionFactory factory : new HybridEncryptionFactory[] {
                            new HybridEncryptionFactory(asymmetricFactory, symmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, asymmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, symmetricFactory) }) {
                        log.info(" * %s", factory.getAlgorithm().getAlgorithm());
                        try {
                            testCipherStream(factory, "1234567890", "0987654321");
                            testCipherStream(factory, "0987654321", "1234567890");
                        } catch (final IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
        }
    }

    private void testCipherStream(final HybridEncryptionFactory factory, final String... payloads) throws IOException {
        final FastByteArrayOutputStream encryptedOutputStream = new FastByteArrayOutputStream();
        final OutputStream encryptingStream = factory.newEncryptor(encryptedOutputStream);

        final FastByteArrayInputStream encryptedInputStream = new FastByteArrayInputStream(Bytes.EMPTY_ARRAY);
        final InputStream decryptingStream = factory.newDecryptor(encryptedInputStream);

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
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        final byte[] key = ByteBuffers.allocateByteArray(AesKeySize.DEFAULT.getBytes());
        random.nextBytes(key);
        derivedKeyProvider = DerivedKeyProvider
                .fromRandom(SymmetricEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        for (final ISymmetricCipherAlgorithm symmetricAlgorithm : ISymmetricCipherAlgorithm.values()) {
            final byte[] cipherKey = derivedKeyProvider.newDerivedKey("cipher-key".getBytes(),
                    symmetricAlgorithm.getDefaultKeySizeBits());
            final CipherDerivedIV derivedIV = new CipherDerivedIV(symmetricAlgorithm, derivedKeyProvider);
            final CipherCountedIV countedIV = new CipherCountedIV(symmetricAlgorithm);
            final CipherPresharedIV presharedIV = new CipherPresharedIV(symmetricAlgorithm, derivedKeyProvider
                    .newDerivedKey("preshared-iv".getBytes(), symmetricAlgorithm.getIvSize() * Byte.SIZE));
            final CipherRandomIV randomIV = new CipherRandomIV(symmetricAlgorithm);
            for (final ICipherIV iv : Arrays.asList(randomIV, derivedIV, countedIV, presharedIV)) {
                final SymmetricEncryptionFactory symmetricFactory = new SymmetricEncryptionFactory(symmetricAlgorithm,
                        cipherKey, iv);
                for (final IAsymmetricCipherAlgorithm asymmetricAlgorithm : IAsymmetricCipherAlgorithm.values()) {
                    log.info("%s with %s and %s", asymmetricAlgorithm.getAlgorithm(), symmetricAlgorithm.getAlgorithm(),
                            iv.getClass().getSimpleName());
                    final AsymmetricEncryptionFactory asymmetricFactory = new AsymmetricEncryptionFactory(
                            asymmetricAlgorithm, derivedKeyProvider);
                    for (final HybridEncryptionFactory factory : new HybridEncryptionFactory[] {
                            new HybridEncryptionFactory(asymmetricFactory, symmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, asymmetricFactory),
                            new HybridEncryptionFactory(symmetricFactory, symmetricFactory) }) {
                        log.info(" * %s", factory.getAlgorithm().getAlgorithm());
                        try {
                            testStreamingCipherStream(factory, "1234567890", "0987654321");
                            testStreamingCipherStream(factory, "0987654321", "1234567890");
                        } catch (final IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                }
            }
        }
    }

    private void testStreamingCipherStream(final HybridEncryptionFactory factory, final String... payloads)
            throws IOException {
        final FastByteArrayOutputStream encryptedOutputStream = new FastByteArrayOutputStream();
        final OutputStream encryptingStream = factory.newStreamingEncryptor(encryptedOutputStream);

        final FastByteArrayInputStream encryptedInputStream = new FastByteArrayInputStream(Bytes.EMPTY_ARRAY);
        final InputStream decryptingStream = factory.newStreamingDecryptor(encryptedInputStream);

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
