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
import de.invesdwin.context.security.crypto.encryption.cipher.wrapper.ByteBufferAlgorithmParameterSpec;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.ALazyDelegateInputStream;
import de.invesdwin.util.streams.ALazyDelegateOutputStream;
import de.invesdwin.util.streams.InputStreams;
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

    private static final int ENCRYPTEDDATAKEYLENGTH_SIZE = Integer.BYTES;
    private static final int ENCRYPTEDDATAKEYLENGTH_INDEX = 0;
    private static final int ENCRYPTEDDATAKEY_INDEX = ENCRYPTEDDATAKEYLENGTH_INDEX + ENCRYPTEDDATAKEYLENGTH_SIZE;

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

    @SuppressWarnings("deprecation")
    @Override
    public int init(final CipherMode mode, final ICipher cipher, final IKey key, final IByteBuffer paramBuffer) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        final ByteBufferAlgorithmParameterSpec params = new ByteBufferAlgorithmParameterSpec(paramBuffer);
        hybridCipher.init(mode, key, params);
        return params.getSize();
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        return new ALazyDelegateOutputStream() {
            @Override
            protected OutputStream newDelegate() {
                //prepare secret key and iv
                final IKey randomDataKey = dataEncryptionFactory.getKey().newRandomInstance();
                final IByteBuffer decryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                try {
                    final int decryptedSize = randomDataKey.toBuffer(decryptedDataKeyBuffer);

                    //encrypt secret key and iv and send it over the wire with the encrypted length
                    final IByteBuffer encryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                    try {
                        final int encryptedDataKeySize = keyEncryptionFactory.encrypt(
                                decryptedDataKeyBuffer.sliceTo(decryptedSize), encryptedDataKeyBuffer,
                                hybridCipher.getKeyCipher());
                        OutputStreams.writeInt(out, encryptedDataKeySize);
                        encryptedDataKeyBuffer.getBytesTo(0, out, encryptedDataKeySize);
                    } catch (final IOException e) {
                        throw new RuntimeException(e);
                    } finally {
                        ByteBuffers.EXPANDABLE_POOL.returnObject(encryptedDataKeyBuffer);
                    }

                } finally {
                    ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedDataKeyBuffer);
                }

                //switch to symmetric encryption using the secret key and iv
                return dataEncryptionFactory.newEncryptor(out, hybridCipher.getDataCipher(), randomDataKey);
            }
        };
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final IByteBuffer encryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                final IByteBuffer decryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                try {
                    final int encryptedDataKeySize = InputStreams.readInt(in);
                    encryptedDataKeyBuffer.putBytesTo(0, in, encryptedDataKeySize);
                    final int decryptedSize = keyEncryptionFactory.decrypt(
                            encryptedDataKeyBuffer.sliceTo(encryptedDataKeySize), decryptedDataKeyBuffer,
                            hybridCipher.getKeyCipher());
                    final IKey randomDataKey = dataEncryptionFactory.getKey()
                            .fromBuffer(decryptedDataKeyBuffer.sliceTo(decryptedSize));
                    return dataEncryptionFactory.newDecryptor(in, hybridCipher.getDataCipher(), randomDataKey);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                } finally {
                    ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedDataKeyBuffer);
                    ByteBuffers.EXPANDABLE_POOL.returnObject(encryptedDataKeyBuffer);
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
                //prepare secret key and iv
                final IKey randomDataKey = dataEncryptionFactory.getKey().newRandomInstance();
                final IByteBuffer decryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                try {
                    final int decryptedSize = randomDataKey.toBuffer(decryptedDataKeyBuffer);

                    //encrypt secret key and iv and send it over the wire with the encrypted length
                    final IByteBuffer encryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                    try {
                        final int encryptedDataKeySize = keyEncryptionFactory.encrypt(
                                decryptedDataKeyBuffer.sliceTo(decryptedSize), encryptedDataKeyBuffer,
                                hybridCipher.getKeyCipher());
                        OutputStreams.writeInt(out, encryptedDataKeySize);
                        encryptedDataKeyBuffer.getBytesTo(0, out, encryptedDataKeySize);
                    } catch (final IOException e) {
                        throw new RuntimeException(e);
                    } finally {
                        ByteBuffers.EXPANDABLE_POOL.returnObject(encryptedDataKeyBuffer);
                    }

                } finally {
                    ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedDataKeyBuffer);
                }

                //switch to symmetric encryption using the secret key and iv
                return dataEncryptionFactory.newStreamingEncryptor(out, hybridCipher.getDataCipher(), randomDataKey);
            }
        };
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;
        return new ALazyDelegateInputStream() {
            @Override
            protected InputStream newDelegate() {
                final IByteBuffer encryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                final IByteBuffer decryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
                try {
                    final int encryptedDataKeySize = InputStreams.readInt(in);
                    encryptedDataKeyBuffer.putBytesTo(0, in, encryptedDataKeySize);
                    final int decryptedSize = keyEncryptionFactory.decrypt(
                            encryptedDataKeyBuffer.sliceTo(encryptedDataKeySize), decryptedDataKeyBuffer,
                            hybridCipher.getKeyCipher());
                    final IKey randomDataKey = dataEncryptionFactory.getKey()
                            .fromBuffer(decryptedDataKeyBuffer.sliceTo(decryptedSize));
                    return dataEncryptionFactory.newStreamingDecryptor(in, hybridCipher.getDataCipher(), randomDataKey);
                } catch (final IOException e) {
                    throw new RuntimeException(e);
                } finally {
                    ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedDataKeyBuffer);
                    ByteBuffers.EXPANDABLE_POOL.returnObject(encryptedDataKeyBuffer);
                }
            }
        };
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;

        //prepare secret key and iv
        final IKey randomDataKey = dataEncryptionFactory.getKey().newRandomInstance();
        final IByteBuffer decryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
        try {
            final int decryptedSize = randomDataKey.toBuffer(decryptedDataKeyBuffer);

            //encrypt secret key and iv and send it over the wire with the encrypted length
            final int encryptedDataKeySize = keyEncryptionFactory.encrypt(decryptedDataKeyBuffer.sliceTo(decryptedSize),
                    dest.sliceFrom(ENCRYPTEDDATAKEY_INDEX), hybridCipher.getKeyCipher());
            dest.putInt(ENCRYPTEDDATAKEYLENGTH_INDEX, encryptedDataKeySize);

            final int payloadIndex = ENCRYPTEDDATAKEY_INDEX + encryptedDataKeySize;
            final int payloadSize = dataEncryptionFactory.encrypt(src, dest.sliceFrom(payloadIndex),
                    hybridCipher.getDataCipher(), randomDataKey);

            return payloadIndex + payloadSize;
        } finally {
            ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedDataKeyBuffer);
        }
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final HybridCipher hybridCipher = (HybridCipher) cipher;

        final int encryptedDataKeySize = src.getInt(ENCRYPTEDDATAKEYLENGTH_INDEX);

        final IByteBuffer decryptedDataKeyBuffer = ByteBuffers.EXPANDABLE_POOL.borrowObject();
        final IKey randomDataKey;
        try {
            final int decryptedSize = keyEncryptionFactory.decrypt(
                    src.slice(ENCRYPTEDDATAKEY_INDEX, encryptedDataKeySize), decryptedDataKeyBuffer,
                    hybridCipher.getKeyCipher());
            randomDataKey = dataEncryptionFactory.getKey().fromBuffer(decryptedDataKeyBuffer.sliceTo(decryptedSize));
        } finally {
            ByteBuffers.EXPANDABLE_POOL.returnObject(decryptedDataKeyBuffer);
        }

        final int payloadIndex = ENCRYPTEDDATAKEY_INDEX + encryptedDataKeySize;
        return dataEncryptionFactory.decrypt(src.sliceFrom(payloadIndex), dest, hybridCipher.getDataCipher(),
                randomDataKey);
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> serde, final IKey key) {
        return new EncryptionDelegateSerde<>(serde, this, key);
    }

}
