package de.invesdwin.context.security.crypto.encryption.cipher.symmetric.stream.util.input;

import java.io.Closeable;
import java.io.IOException;

/**
 * Adapted from: org.apache.commons.crypto.stream.input.ChannelInput
 */
public interface ICipherInput extends Closeable {
    int read(java.nio.ByteBuffer dst) throws IOException;

    long skip(long n) throws IOException;

    int available() throws IOException;

    int read(long position, byte[] buffer, int offset, int length) throws IOException;

    void seek(long position) throws IOException;

    @Override
    void close() throws IOException;
}
