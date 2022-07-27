package de.invesdwin.context.security.crypto.verification;

import java.io.InputStream;
import java.io.OutputStream;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashInputStream;
import de.invesdwin.context.security.crypto.verification.hash.stream.LayeredHashOutputStream;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Used to authenticate messages (e.g. with HmacSHA256)
 */
public interface IVerificationFactory {

    IHashAlgorithm getAlgorithm();

    void init(IHash hash);

    LayeredHashOutputStream newHashOutputStream(OutputStream out);

    LayeredHashInputStream newHashInputStream(InputStream in);

    byte[] newHash(IByteBuffer src);

    byte[] newHash(IByteBuffer src, IHash hash);

    int putHash(IByteBuffer dest, int destSignatureIndex);

    int putHash(IByteBuffer dest, int destSignatureIndex, IHash hash);

    int copyAndHash(IByteBuffer src, IByteBuffer dest);

    int copyAndHash(IByteBuffer src, IByteBuffer dest, IHash hash);

    int verifyAndCopy(IByteBuffer src, IByteBuffer dest);

    int verifyAndCopy(IByteBuffer src, IByteBuffer dest, IHash hash);

    IByteBuffer verifyAndSlice(IByteBuffer src);

    IByteBuffer verifyAndSlice(IByteBuffer src, IHash hash);

    <T> ISerde<T> maybeWrap(ISerde<T> delegate);

}
