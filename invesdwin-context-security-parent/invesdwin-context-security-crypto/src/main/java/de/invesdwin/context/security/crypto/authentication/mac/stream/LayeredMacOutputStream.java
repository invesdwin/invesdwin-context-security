package de.invesdwin.context.security.crypto.authentication.mac.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.util.streams.ASimpleDelegateOutputStream;

@NotThreadSafe
public class LayeredMacOutputStream extends ASimpleDelegateOutputStream {
    protected final IMac mac;

    public LayeredMacOutputStream(final OutputStream delegate, final IMac mac, final Key key) {
        super(delegate);
        this.mac = mac;
        mac.init(key);
    }

    public void init() {
        mac.reset();
    }

    @Override
    public void write(final int b) throws IOException {
        super.write(b);
        mac.update((byte) b);
    }

    @Override
    public void write(final byte[] b) throws IOException {
        super.write(b);
        mac.update(b);
    }

    @Override
    public void write(final byte[] b, final int off, final int len) throws IOException {
        super.write(b, off, len);
        mac.update(b, off, len);
    }

    public byte[] doFinal() {
        //resets the mac to its previous initial state
        return mac.doFinal();
    }

    @Override
    public void close() throws IOException {
        super.close();
        mac.close();
    }

}
