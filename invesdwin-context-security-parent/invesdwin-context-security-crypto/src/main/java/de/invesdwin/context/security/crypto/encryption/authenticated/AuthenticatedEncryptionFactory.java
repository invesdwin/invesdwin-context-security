package de.invesdwin.context.security.crypto.encryption.authenticated;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.encryption.IEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AuthenticatedCipherAlgorithm;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * WARNING: using this is less efficient for streams than doing the authentication from the outside. Thus is because
 * decryption has to buffer the input for the authentication before actually starting to decrypt
 * (https://moxie.org/2011/12/13/the-cryptographic-doom-principle.html). This copy can be prevented when using the
 * approach of: AuthenticatedEncryptionSynchronousReader & AuthenticatedEncryptionSynchronousReader from
 * invesdwin-context-integration-channel
 * 
 * Though for normal encrypt/decrypt calls this class is fine.
 * 
 * Also the AuthenticatedCipher update calls always return a written length of 0 despite writing to the given output.
 * This makes using the cipher directly unsuitable.
 */
@Immutable
public class AuthenticatedEncryptionFactory implements IEncryptionFactory {

    private final AuthenticatedCipherAlgorithm algorithm;
    private final IEncryptionFactory encryptionFactory;
    private final IAuthenticationFactory authenticationFactory;

    public AuthenticatedEncryptionFactory(final IEncryptionFactory encryptionFactory,
            final IAuthenticationFactory authenticationFactory) {
        this.encryptionFactory = encryptionFactory;
        this.authenticationFactory = authenticationFactory;
        this.algorithm = new AuthenticatedCipherAlgorithm(encryptionFactory.getAlgorithm(), authenticationFactory);
    }

    @Override
    public AuthenticatedCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public void init(final ICipher cipher, final int mode, final AlgorithmParameterSpec iv) {
        encryptionFactory.init(cipher, mode, iv);
    }

    public IAuthenticationFactory getAuthenticationFactory() {
        return authenticationFactory;
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
        final int signatureLength = authenticationFactory.putSignature(dest, encryptedLength);
        return encryptedLength + signatureLength;
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        final AuthenticatedCipher cCipher = (AuthenticatedCipher) cipher;
        final int encryptedLength = encryptionFactory.encrypt(src, dest, cCipher.getUnauthenticatedCipher());
        final int signatureLength = authenticationFactory.putSignature(dest, encryptedLength, cCipher.getMac());
        return encryptedLength + signatureLength;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final IByteBuffer payload = authenticationFactory.verifyAndSlice(src);
        final int decryptedLength = encryptionFactory.decrypt(payload, dest);
        return decryptedLength;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest, final ICipher cipher) {
        final AuthenticatedCipher cCipher = (AuthenticatedCipher) cipher;
        final IByteBuffer payload = authenticationFactory.verifyAndSlice(src, cCipher.getMac());
        final int decryptedLength = encryptionFactory.decrypt(payload, dest, cCipher.getUnauthenticatedCipher());
        return decryptedLength;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return authenticationFactory.maybeWrap(encryptionFactory.maybeWrap(delegate));
    }

}
