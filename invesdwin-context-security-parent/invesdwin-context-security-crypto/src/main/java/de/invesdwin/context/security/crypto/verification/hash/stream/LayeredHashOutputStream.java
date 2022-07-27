package de.invesdwin.context.security.crypto.verification.hash.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.streams.ASimpleDelegateOutputStream;

@NotThreadSafe
public class LayeredHashOutputStream extends ASimpleDelegateOutputStream {
    protected final IHash hash;

    public LayeredHashOutputStream(final OutputStream delegate, final IHash hash, final Key key) {
        super(delegate);
        this.hash = hash;
        hash.init(key);
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

    public byte[] doFinal() {
        //resets the mac to its previous initial state
        return hash.doFinal();
    }

    @Override
    public void close() throws IOException {
        super.close();
        hash.close();
    }

}
