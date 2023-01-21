package de.invesdwin.context.security.crypto.verification.hash.stream;

import java.io.IOException;
import java.io.InputStream;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.SimpleDelegateInputStream;

@NotThreadSafe
public class LayeredHashInputStream extends SimpleDelegateInputStream {
    protected final IHash hash;

    public LayeredHashInputStream(final InputStream delegate, final IHash hash, final IKey key) {
        super(delegate);
        this.hash = hash;
        hash.init(HashMode.Verify, key);
    }

    public void init() {
        hash.reset();
    }

    @Override
    public int read() throws IOException {
        final int b = super.read();
        if (b > 0) {
            hash.update((byte) b);
        }
        return b;
    }

    @Override
    public int read(final byte[] b) throws IOException {
        final int n = super.read(b);
        if (n > 0) {
            hash.update(b, 0, n);
        }
        return n;
    }

    @Override
    public byte[] readAllBytes() throws IOException {
        final byte[] bytes = super.readAllBytes();
        if (bytes.length > 0) {
            hash.update(bytes);
        }
        return bytes;
    }

    @Override
    public int readNBytes(final byte[] b, final int off, final int len) throws IOException {
        final int n = super.readNBytes(b, off, len);
        if (n > 0) {
            hash.update(b, off, n);
        }
        return n;
    }

    @Override
    public byte[] readNBytes(final int len) throws IOException {
        final byte[] bytes = super.readNBytes(len);
        if (bytes.length > 0) {
            hash.update(bytes);
        }
        return bytes;
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        final int n = super.read(b, off, len);
        if (n > 0) {
            hash.update(b, off, n);
        }
        return n;
    }

    public IHash getHash() {
        return hash;
    }

    @Override
    public void close() throws IOException {
        super.close();
        hash.close();
    }

}
