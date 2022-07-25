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

    void init(ICipher cipher, int mode, AlgorithmParameterSpec iv);

    OutputStream newEncryptor(OutputStream out);

    InputStream newDecryptor(InputStream in);

    int encrypt(IByteBuffer src, IByteBuffer dest);

    int decrypt(IByteBuffer src, IByteBuffer dest);

    <T> ISerde<T> maybeWrap(ISerde<T> delegate);

}
