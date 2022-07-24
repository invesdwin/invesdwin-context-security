package de.invesdwin.context.security.crypto.authentication;

import java.io.InputStream;
import java.io.OutputStream;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.authentication.mac.algorithm.IMacAlgorithm;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacInputStream;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacOutputStream;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

/**
 * Used to authenticate messages (e.g. with HmacSHA256)
 */
public interface IAuthenticationFactory {

    IMacAlgorithm getAlgorithm();

    LayeredMacOutputStream newSignatureOutputStream(OutputStream out);

    LayeredMacInputStream newVerificationInputStream(InputStream in);

    byte[] newSignature(IByteBuffer src);

    byte[] newSignature(IByteBuffer src, IMac mac);

    int putSignature(IByteBuffer dest, int destSignatureIndex);

    int putSignature(IByteBuffer dest, int destSignatureIndex, IMac mac);

    int copyAndSign(IByteBuffer src, IByteBuffer dest);

    int copyAndSign(IByteBuffer src, IByteBuffer dest, IMac mac);

    int verifyAndCopy(IByteBuffer src, IByteBuffer dest);

    int verifyAndCopy(IByteBuffer src, IByteBuffer dest, IMac mac);

    IByteBuffer verifyAndSlice(IByteBuffer src);

    IByteBuffer verifyAndSlice(IByteBuffer src, IMac mac);

    <T> ISerde<T> maybeWrap(ISerde<T> delegate);

}
