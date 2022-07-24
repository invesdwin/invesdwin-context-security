package de.invesdwin.context.security.crypto.encryption.cipher;

import java.util.Arrays;

import javax.annotation.concurrent.NotThreadSafe;

import org.junit.jupiter.api.Test;

import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherCountedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherPresharedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherRandomIV;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.ICipherIV;
import de.invesdwin.context.security.crypto.key.DerivedKeyProvider;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.context.test.ATest;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class CipherEncryptionFactoryTest extends ATest {

    @Test
    public void testEncryptionAndDecryption() {
        final DerivedKeyProvider derivedKeyProvider;
        final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
        try {
            final byte[] key = ByteBuffers.allocateByteArray(AesKeyLength._256.getBytes());
            random.nextBytes(key);
            derivedKeyProvider = DerivedKeyProvider
                    .fromRandom(CipherEncryptionFactoryTest.class.getSimpleName().getBytes(), key);
        } finally {
            CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
        }
        for (final AesAlgorithm algorithm : AesAlgorithm.values()) {
            final CipherDerivedIV derivedIV = new CipherDerivedIV(algorithm, derivedKeyProvider);
            final CipherCountedIV countedIV = new CipherCountedIV(algorithm);
            final CipherPresharedIV presharedIV = new CipherPresharedIV(algorithm,
                    derivedKeyProvider.newDerivedKey("preshared-iv".getBytes(), algorithm.getIvSize()));
            final CipherRandomIV randomIV = new CipherRandomIV(algorithm);
            for (final ICipherIV iv : Arrays.asList(randomIV, derivedIV, countedIV, presharedIV)) {
                final CipherEncryptionFactory factory = new CipherEncryptionFactory(algorithm,
                        derivedKeyProvider.getKey(), iv);
                testEncryptionAndDecryption(factory);
            }
        }
    }

    private void testEncryptionAndDecryption(final CipherEncryptionFactory factory) {
        final String srcStr = "1234567890";
        final IByteBuffer src = ByteBuffers.wrap(srcStr.getBytes());
        final IByteBuffer encrypted = ByteBuffers.allocateExpandable();
        final int encryptedSize = factory.encrypt(src, encrypted);
        final IByteBuffer dst = ByteBuffers.allocateExpandable();
        final int decryptedSize = factory.decrypt(encrypted.sliceTo(encryptedSize), dst);
        Assertions.assertThat(decryptedSize).isEqualTo(src.capacity());
        Assertions.assertThat(ByteBuffers.equals(src, dst.sliceTo(decryptedSize))).isTrue();
    }

}
