package de.invesdwin.context.security.crypto.encryption.verified;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.verification.IVerificationFactory;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * WARNING: using this is less efficient for streams than doing the authentication from the outside. Thus is because
 * decryption has to buffer the input for the authentication before actually starting to decrypt
 * (https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html). This copy can be prevented when using the
 * approach of: VerifiedEncryptionSynchronousReader & VerifiedEncryptionSynchronousReader from
 * invesdwin-context-integration-channel
 * 
 * Though for normal encrypt/decrypt calls this class is fine.
 * 
 * Also the VerifiedCipher update calls always return a written length of 0 despite writing to the given output (same as
 * com.sun.crypto.provider.GaloisCounterMode.GCMDecrypt.doUpdate(byte[], int, int, byte[], int)). This makes using the
 * cipher directly unsuitable (except for java.nio.ByteBuffer which stores the output position internally).
 */
@Immutable
public class VerifiedEncryptionFactory implements IEncryptionFactory {

    private final VerifiedCipherAlgorithm algorithm;
    private final IEncryptionFactory encryptionFactory;
    private final IVerificationFactory verificationFactory;

    public VerifiedEncryptionFactory(final IEncryptionFactory encryptionFactory,
            final IVerificationFactory verificationFactory) {
        this.encryptionFactory = encryptionFactory;
        this.verificationFactory = verificationFactory;
        this.algorithm = new VerifiedCipherAlgorithm(encryptionFactory.getAlgorithm(), verificationFactory);
    }

    @Override
    public VerifiedCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public void init(final ICipher cipher, final int mode, final AlgorithmParameterSpec param) {
        encryptionFactory.init(cipher, mode, param);
    }

    public IVerificationFactory getVerificationFactory() {
        return verificationFactory;
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out) {
        return newEncryptor(out, algorithm.newCipher());
    }

    @Override
    public OutputStream newEncryptor(final OutputStream out, final ICipher cipher) {
        return encryptionFactory.newEncryptor(out, cipher);
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        return newDecryptor(in, algorithm.newCipher());
    }

    @Override
    public InputStream newDecryptor(final InputStream in, final ICipher cipher) {
        return encryptionFactory.newDecryptor(in, cipher);
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        final int encryptedLength = encryptionFactory.encrypt(src, dest);
        final int signatureLength = verificationFactory.putHash(dest, encryptedLength);
        return encryptedLength + signatureLength;
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        final VerifiedCipher cCipher = (VerifiedCipher) cipher;
        final int encryptedLength = encryptionFactory.encrypt(src, dest, cCipher.getUnverifiedCipher());
        final int signatureLength = verificationFactory.putHash(dest, encryptedLength, cCipher.getHash());
        return encryptedLength + signatureLength;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final IByteBuffer payload = verificationFactory.verifyAndSlice(src);
        final int decryptedLength = encryptionFactory.decrypt(payload, dest);
        return decryptedLength;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        final VerifiedCipher cCipher = (VerifiedCipher) cipher;
        final IByteBuffer payload = verificationFactory.verifyAndSlice(src, cCipher.getHash());
        final int decryptedLength = encryptionFactory.decrypt(payload, dest, cCipher.getUnverifiedCipher());
        return decryptedLength;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return verificationFactory.maybeWrap(encryptionFactory.maybeWrap(delegate));
    }

}
