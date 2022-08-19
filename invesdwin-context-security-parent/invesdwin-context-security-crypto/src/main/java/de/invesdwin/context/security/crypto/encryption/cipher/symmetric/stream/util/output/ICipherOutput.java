package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.output;

import java.io.Closeable;
import java.io.IOException;

/**
 * Adapted from: org.apache.commons.crypto.stream.output.Output
 */
public interface ICipherOutput extends Closeable {

    int write(java.nio.ByteBuffer src) throws IOException;

    void flush() throws IOException;

    @Override
    void close() throws IOException;
}
