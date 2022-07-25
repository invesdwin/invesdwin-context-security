package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class AuthenticatedEncryptionFactory implements IEncryptionFactory {

    private final IEncryptionFactory encryptionFactory;
    private final IAuthenticationFactory authenticationFactory;

    public AuthenticatedEncryptionFactory(final IEncryptionFactory encryptionFactory,
            final IAuthenticationFactory authenticationFactory) {
        this.encryptionFactory = encryptionFactory;
        this.authenticationFactory = authenticationFactory;
    }

    @Override
    public ICipherAlgorithm getAlgorithm() {
        return encryptionFactory.getAlgorithm();
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
        throw new UnsupportedOperationException();
    }

    @Override
    public InputStream newDecryptor(final InputStream in) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int encrypt(final IByteBuffer src, final IByteBuffer dest) {
        final int encryptedLength = encryptionFactory.encrypt(src, dest);
        final int signatureLength = authenticationFactory.putSignature(dest, encryptedLength);
        return encryptedLength + signatureLength;
    }

    @Override
    public int decrypt(final IByteBuffer src, final IByteBuffer dest) {
        final int encryptedLength = encryptionFactory.encrypt(src, dest);
        final int signatureLength = authenticationFactory.putSignature(dest, encryptedLength);
        return encryptedLength + signatureLength;
    }

    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return authenticationFactory.maybeWrap(encryptionFactory.maybeWrap(delegate));
    }

}
