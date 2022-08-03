package de.invesdwin.context.security.crypto.encryption.cipher.hybrid;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.EncryptionDelegateSerde;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.hybrid.algorithm.HybridCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.hybrid.wrapper.HybridCipher;
import de.invesdwin.context.security.crypto.encryption.cipher.pool.MutableIvParameterSpec;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingSymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.StreamingSymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.SymmetricCipherInputStream;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.SymmetricCipherOutputStream;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGeneratorObjectPool;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.ALazyDelegateInputStream;
import de.invesdwin.util.streams.ALazyDelegateOutputStream;
import de.invesdwin.util.streams.OutputStreams;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * This will encrypt a new random symmetric key with the asymmetric encryption factory. The key size is taken from the
 * symmetric encryption factory without using the actual key there. Only the asymmetric keys are used.
 * 
 * https://security.stackexchange.com/questions/149064/is-it-possible-to-combine-rsa-and-aes
 * https://en.wikipedia.org/wiki/Hybrid_cryptosystem
 * 
 * This is not fast for single encryptions/decryptions when asymmetric encryption is used each time (with the benefit
 * that one can encrypt larger payloads than the rsa key size). Though for input/output streams, a switch to symmetric
 * encryption also provides a significant performance boost. This hybrid approach can be used if a public/private key
 * pair is the only means of exhanged key for both parties. If a symmetric key can be securely exchanged or
 * generated/derived somehow (see IDerivedKeyProvider), then this hybrid approach can be skipped and one can go directly
 * with symmetric encryption.
 * 
 * Though another benefit for streams of this hybrid approach is that each symmetric encryption uses a different key
 * (similar to a session key). This would otherwise need to be ensured by a key exchange mechanism separately. So using
 * password based symmetric encryption to switch to a session based symmetric encryption can also make sense here. One
 * can rotate session keys by reinitializing the stream.
 * 
 * HybridEncryptionFactory instances can be nested arbitrarily. Though when does it make sense to combine more than two
 * encryption algorithms? The transmitted keys are only as secure as the outer most secret key.
 */
@Immutable
public class HybridEncryptionFactory implements IEncryptionFactory {

    private static final int ENCRYPTEDSECRETLENGTH_SIZE = Integer.BYTES;
    private static final int ENCRYPTEDSECRETLENGTH_INDEX = 0;
    private static final int ENCRYPTEDSECRET_INDEX = ENCRYPTEDSECRETLENGTH_INDEX + ENCRYPTEDSECRETLENGTH_SIZE;

    private final IEncryptionFactory keyEncryptionFactory;
    private final IEncryptionFactory dataEncryptionFactory;
    private final HybridCipherAlgorithm hybridAlgorithm;

    public HybridEncryptionFactory(final IEncryptionFactory keyEncryptionFactory,
            final IEncryptionFactory dataEncryptionFactory) {
        this.keyEncryptionFactory = keyEncryptionFactory;
        this.dataEncryptionFactory = dataEncryptionFactory;

        this.hybridAlgorithm = new HybridCipherAlgorithm(keyEncryptionFactory, dataEncryptionFactory);
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return hybridAlgorithm;
    }

    @Override
    public IKey getKey() {
        return keyEncryptionFactory.getKey();
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                //prepare secret key and iv
                final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
                final byte[] symmetricKey = new byte[secondKeySize];
                try {
                    random.nextBytes(symmetricKey);
                } finally {
                    CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
                }
                final MutableIvParameterSpec iv = new MutableIvParameterSpec(
                        ByteBuffers.allocateByteArray(symmetricCipherIV.getAlgorithm().getIvSize()));

                //combine secret key and iv
                final IByteBuffer decryptedSecretBuffer = ByteBuffers
                        .allocate(symmetricKey.length + symmetricCipherIV.getIvBlockSize());
                decryptedSecretBuffer.putBytes(0, symmetricKey);
                final int ivIndex = symmetricKey.length;
                symmetricCipherIV.putIV(decryptedSecretBuffer.sliceFrom(ivIndex), iv);

                //encrypt secret key and iv and send it over the wire with the encrypted length
                final IByteBuffer encryptedSecretBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                try {
                    final int encryptedLength = keyEncryptionFactory.encrypt(decryptedSecretBuffer,
                            decryptedSecretBuffer, hybridCipher.getKeyCipher());
                    OutputStreams.writeInt(out, encryptedLength);
                    encryptedSecretBuffer.getBytesTo(0, out, encryptedLength);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                } finally {
                    ByteBuffers.EXPANDABLE_POOL.returnObject(encryptedSecretBuffer);
                }

                //switch to symmetric encryption using the secret key and iv
                try {
                    return new SymmetricCipherOutputStream(dataEncryptionFactory.getAlgorithm(), out,
                            hybridCipher.getDataCipher(), symmetricKey, iv.getIV());
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final byte[] iv = symmetricCipherIV.getNewIV(in);
                try {
                    return new SymmetricCipherInputStream(algorithm, in, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
                final byte[] symmetricKey = new byte[secondKeySize];
                try {
                    random.nextBytes(symmetricKey);
                } finally {
                    CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
                }
                final MutableIvParameterSpec iv = new MutableIvParameterSpec(
                        ByteBuffers.allocateByteArray(symmetricCipherIV.getAlgorithm().getIvSize()));

                final IByteBuffer decryptedSecretBuffer = ByteBuffers
                        .allocate(symmetricKey.length + symmetricCipherIV.getIvBlockSize());
                decryptedSecretBuffer.putBytes(0, symmetricKey);
                final int ivIndex = symmetricKey.length;
                symmetricCipherIV.putIV(decryptedSecretBuffer.sliceFrom(ivIndex), iv);

                final IByteBuffer encryptedSecretBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                try {
                    final int encryptedLength = keyEncryptionFactory.encrypt(decryptedSecretBuffer,
                            decryptedSecretBuffer, hybridCipher.getKeyCipher());
                    OutputStreams.writeInt(out, encryptedLength);
                    encryptedSecretBuffer.getBytesTo(0, out, encryptedLength);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                } finally {
                    ByteBuffers.EXPANDABLE_POOL.returnObject(encryptedSecretBuffer);
                }

                try {
                    return new StreamingSymmetricCipherOutputStream(dataEncryptionFactory.getAlgorithm(), out,
                            hybridCipher.getDataCipher(), symmetricKey, iv.getIV());
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final byte[] iv = symmetricCipherIV.getNewIV(in);
                try {
                    return new StreamingSymmetricCipherInputStream(algorithm, in, cipher, key, iv);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        final MutableIvParameterSpec iv = symmetricCipherIV.borrowDestIV();
        try {
            //prepare secret key and iv
            final CryptoRandomGenerator random = CryptoRandomGeneratorObjectPool.INSTANCE.borrowObject();
            final byte[] symmetricKey = new byte[secondKeySize];
            try {
                random.nextBytes(symmetricKey);
            } finally {
                CryptoRandomGeneratorObjectPool.INSTANCE.returnObject(random);
            }

            //combine secret key and iv
            final IByteBuffer decryptedSecretBuffer = ByteBuffers
                    .allocate(symmetricKey.length + symmetricCipherIV.getIvBlockSize());
            decryptedSecretBuffer.putBytes(0, symmetricKey);
            final int ivIndex = symmetricKey.length;
            symmetricCipherIV.putIV(decryptedSecretBuffer.sliceFrom(ivIndex), iv);

            //encrypt secret key and iv and send it over the wire with the encrypted length
            final int encryptedSecretSize = keyEncryptionFactory.encrypt(decryptedSecretBuffer,
                    dest.sliceFrom(ENCRYPTEDSECRET_INDEX), hybridCipher.getKeyCipher());
            dest.putInt(ENCRYPTEDSECRETLENGTH_INDEX, encryptedSecretSize);

            //finally add the symmetrically encrypted payload
            final int payloadIndex = ENCRYPTEDSECRET_INDEX + encryptedSecretSize;
            final ICipher symmetricCipher = hybridCipher.getDataCipher();
            symmetricCipher.init(CipherMode.Encrypt, dataEncryptionFactory.getAlgorithm().wrapKey(symmetricKey),
                    symmetricCipherIV.wrapParam(iv));
            final IByteBuffer payloadBuffer = dest.sliceFrom(payloadIndex);
            final int payloadLength = symmetricCipher.doFinal(src, payloadBuffer);
            return payloadIndex + payloadLength;
        } finally {
            symmetricCipherIV.returnDestIV(iv);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final MutableIvParameterSpec iv = symmetricCipherIV.borrowDestIV();
        try {
            symmetricCipherIV.getIV(src, iv);
            init(cipher, CipherMode.Decrypt, symmetricCipherIV.wrapParam(iv));
            final IByteBuffer payloadBuffer = src.sliceFrom(symmetricCipherIV.getIvBlockSize());
            final int length = cipher.doFinal(payloadBuffer, dest);
            return length;
        } finally {
            symmetricCipherIV.returnDestIV(iv);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde, final IKey key) {
        return new EncryptionDelegateSerde<>(serde, this, key);
    }

}
