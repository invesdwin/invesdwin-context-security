package de.invesdwin.context.security.crypto.encryption.verified;

import java.io.InputStream;
import java.io.OutputStream;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.verified.algorithm.AVerifiedCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.verified.wrapper.VerifiedCipher;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * WARNING: using this is less efficient for streams than doing the authentication from the outside. This is because
 * decryption has to buffer the input for the authentication before actually starting to decrypt
 * (https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html). This copy can be prevented when using the
 * approach of: VerifiedEncryptionSynchronousReader & VerifiedEncryptionSynchronousReader from
 * invesdwin-context-integration-channel
 * 
 * Though for normal encrypt/decrypt calls this class is fine.
 * 
 * Also the VerifiedCipher update calls always return a written length of 0 despite writing to the given output (same as
 * com.sun.crypto.provider.GaloisCounterMode.GCMDecrypt.doUpdate). This makes using the cipher directly unsuitable
 * (except for java.nio.ByteBuffer which stores the output position internally).
 */
@Immutable
public class VerifiedEncryptionFactory implements IEncryptionFactory {

    private final AVerifiedCipherAlgorithm algorithm;
    private final IEncryptionFactory encryptionFactory;
    private final IVerificationFactory verificationFactory;
    private final VerifiedCipherKey key;

    public VerifiedEncryptionFactory(final IEncryptionFactory encryptionFactory,
            final IVerificationFactory verificationFactory) {
        this.encryptionFactory = encryptionFactory;
        this.verificationFactory = verificationFactory;
        this.algorithm = AVerifiedCipherAlgorithm.wrap(encryptionFactory, verificationFactory);
        this.key = new VerifiedCipherKey(encryptionFactory.getKey(), verificationFactory.getKey());
    }

    @Override
    public AVerifiedCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public VerifiedCipherKey getKey() {
        return key;
    }

    public IVerificationFactory getVerificationFactory() {
        return verificationFactory;
    }

    @SuppressWarnings("deprecation")
    @Override
    public int init(final CipherMode mode, final ICipher cipher, final IKey key, final IByteBuffer paramBuffer) {
        final VerifiedCipher cCipher = (VerifiedCipher) cipher;
        return cCipher.init(mode, key, paramBuffer);
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        return encryptionFactory.newEncryptor(out, cipher, key);
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return encryptionFactory.newDecryptor(in, cipher, key);
    }

    @Override
    public OutputStream newStreamingEncryptor(final OutputStream out, final ICipher cipher, final IKey key) {
        return encryptionFactory.newStreamingEncryptor(out, cipher, key);
    }

    @Override
    public InputStream newStreamingDecryptor(final InputStream in, final ICipher cipher, final IKey key) {
        return encryptionFactory.newStreamingDecryptor(in, cipher, key);
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final VerifiedCipher cCipher = (VerifiedCipher) cipher;
        final VerifiedCipherKey cKey = (VerifiedCipherKey) key;
        final int encryptedLength = encryptionFactory.encrypt(src, dest, cCipher.getUnverifiedCipher(),
                cKey.getEncryptionKey());
        final int signatureLength = verificationFactory.putHash(dest, encryptedLength, cCipher.getHash(),
                cKey.getVerificationKey());
        return encryptedLength + signatureLength;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher, final IKey key) {
        final VerifiedCipher cCipher = (VerifiedCipher) cipher;
        final VerifiedCipherKey cKey = (VerifiedCipherKey) key;

        final IByteBuffer payload = verificationFactory.verifyAndSlice(src, cCipher.getHash(),
                cKey.getVerificationKey());
        final int decryptedLength = encryptionFactory.decrypt(payload, dest, cCipher.getUnverifiedCipher(),
                cKey.getEncryptionKey());
        return decryptedLength;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate, final IKey key) {
        final VerifiedCipherKey cKey = (VerifiedCipherKey) key;
        return verificationFactory.maybeWrap(encryptionFactory.maybeWrap(delegate, cKey.getEncryptionKey()),
                cKey.getVerificationKey());
    }

}
