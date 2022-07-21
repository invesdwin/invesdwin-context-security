package de.invesdwin.context.security.crypto.authentication;

import java.io.InputStream;
import java.io.OutputStream;

import de.invesdwin.context.security.crypto.authentication.mac.IMacAlgorithm;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacInputStream;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacOutputStream;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IAuthenticationFactory {

    IMacAlgorithm getAlgorithm();

    LayeredMacOutputStream newMacOutputStream(OutputStream out);

    LayeredMacInputStream newMacInputStream(InputStream in);

    byte[] mac(IByteBuffer src);

    int sign(IByteBuffer src, IByteBuffer dest);

    int verify(IByteBuffer src, IByteBuffer dest);

    <T> ISerde<T> maybeWrap(ISerde<T> delegate);

}
