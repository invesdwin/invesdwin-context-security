package de.invesdwin.context.security.crypto.authentication.mac;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.AuthenticatingDelegateSerde;
import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.hmac.HmacAlgorithm;
import de.invesdwin.context.security.crypto.authentication.mac.pool.IMac;
import de.invesdwin.context.security.crypto.authentication.mac.stream.ChannelLayeredMacInputStream;
import de.invesdwin.context.security.crypto.authentication.mac.stream.ChannelLayeredMacOutputStream;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacInputStream;
import de.invesdwin.context.security.crypto.authentication.mac.stream.LayeredMacOutputStream;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;
import de.invesdwin.util.marshallers.serde.ISerde;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class MacAuthenticationFactory implements IAuthenticationFactory {

    private final IMacAlgorithm algorithm;
    private final Key key;

    public MacAuthenticationFactory(final byte[] key) {
        this(HmacAlgorithm.DEFAULT, key);
    }

    public MacAuthenticationFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(HmacAlgorithm.DEFAULT, derivedKeyProvider);
    }

    public MacAuthenticationFactory(final IMacAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider.newDerivedKey("mac-key".getBytes(), algorithm.getMacLength()));
    }

    public MacAuthenticationFactory(final IMacAlgorithm algorithm, final byte[] key) {
        this.algorithm = algorithm;
        this.key = algorithm.wrapKey(key);
    }

    @Override
    public IMacAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public LayeredMacOutputStream newMacOutputStream(final OutputStream out) {
        return ChannelLayeredMacOutputStream.maybeWrap(out, algorithm.newMac(), key);
    }

    @Override
    public LayeredMacInputStream newMacInputStream(final InputStream in) {
        return ChannelLayeredMacInputStream.maybeWrap(in, algorithm.newMac(), key);
    }

    @Override
    public byte[] mac(final IByteBuffer src) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            mac.init(key);
            mac.update(src.asNioByteBuffer());
            return mac.doFinal();
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public int sign(final IByteBuffer src, final IByteBuffer dest) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            mac.init(key);
            mac.update(src.asNioByteBuffer());
            final byte[] signature = mac.doFinal();
            dest.putBytes(0, src);
            final int signatureIndex = src.capacity();
            dest.putBytes(signatureIndex, signature);
            return signatureIndex + signature.length;
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public int verify(final IByteBuffer src, final IByteBuffer dest) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            mac.init(key);
            final int signatureIndex = src.remaining(mac.getMacLength());
            final IByteBuffer payloadBuffer = src.sliceTo(signatureIndex);
            mac.update(payloadBuffer.asNioByteBuffer());
            final byte[] calculatedSignature = mac.doFinal();
            for (int i = 0; i < calculatedSignature.length; i++) {
                if (src.getByte(signatureIndex + i) != calculatedSignature[i]) {
                    throw new IllegalArgumentException("Signature mismatch");
                }
            }
            dest.putBytes(0, payloadBuffer);
            return payloadBuffer.capacity();
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return new AuthenticatingDelegateSerde<>(delegate, this);
    }

}