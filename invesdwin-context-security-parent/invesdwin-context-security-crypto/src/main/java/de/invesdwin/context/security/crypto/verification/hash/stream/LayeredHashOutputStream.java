package de.invesdwin.context.security.crypto.verification.hash.stream;

import java.io.IOException;
import java.io.OutputStream;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.delegate.SimpleDelegateOutputStream;

@NotThreadSafe
public class LayeredHashOutputStream extends SimpleDelegateOutputStream {
    protected final IHash hash;

    public LayeredHashOutputStream(final OutputStream delegate, final IHash hash, final IKey key) {
        super(delegate);
        this.hash = hash;
        hash.init(HashMode.Sign, key);
    }

    public void init() {
        hash.reset();
    }

    @Override
    public void write(final int b) throws IOException {
        super.write(b);
        hash.update((byte) b);
    }

    @Override
    public void write(final byte[] b) throws IOException {
        super.write(b);
        hash.update(b);
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        super.write(b, off, len);
        hash.update(b, off, len);
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
