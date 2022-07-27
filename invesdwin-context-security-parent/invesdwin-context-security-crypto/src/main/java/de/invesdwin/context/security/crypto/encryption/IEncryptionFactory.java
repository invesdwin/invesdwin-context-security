package de.invesdwin.context.security.crypto.encryption;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.spec.AlgorithmParameterSpec;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IEncryptionFactory {

    ICipherAlgorithm getAlgorithm();

    void init(ICipher cipher, int mode, AlgorithmParameterSpec param);

    OutputStream newEncryptor(OutputStream out);

    OutputStream newEncryptor(OutputStream out, ICipher cipher);

    InputStream newDecryptor(InputStream in);

    InputStream newDecryptor(InputStream in, ICipher cipher);

    int encrypt(IByteBuffer src, IByteBuffer dest);

    int encrypt(IByteBuffer src, IByteBuffer dest, ICipher cipher);

    int decrypt(IByteBuffer src, IByteBuffer dest);

    int decrypt(IByteBuffer src, IByteBuffer dest, ICipher cipher);

    <T> ISerde<T> maybeWrap(ISerde<T> delegate);

}
