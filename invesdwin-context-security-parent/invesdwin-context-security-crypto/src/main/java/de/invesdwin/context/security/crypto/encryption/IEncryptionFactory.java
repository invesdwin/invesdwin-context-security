package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IEncryptionFactory {

    ICipherAlgorithm getAlgorithm();

    void init(ICipher cipher, int mode, AlgorithmParameterSpec param);

    /**
     * Can only be used to encrypt one payload.
     */
    OutputStream newEncryptor(OutputStream out);

    OutputStream newEncryptor(OutputStream out, ICipher cipher);

    InputStream newDecryptor(InputStream in);

    InputStream newDecryptor(InputStream in, ICipher cipher);

    /**
     * Can be used to encrypt multiple messages.
     */
    OutputStream newStreamingEncryptor(OutputStream out);

    OutputStream newStreamingEncryptor(OutputStream out, ICipher cipher);

    InputStream newStreamingDecryptor(InputStream in);

    InputStream newStreamingDecryptor(InputStream in, ICipher cipher);

    int encrypt(IByteBuffer src, IByteBuffer dest);

    int encrypt(IByteBuffer src, IByteBuffer dest, ICipher cipher);

    int decrypt(IByteBuffer src, IByteBuffer dest);

    int decrypt(IByteBuffer src, IByteBuffer dest, ICipher cipher);

    <T> ISerde<T> maybeWrap(ISerde<T> delegate);

}
