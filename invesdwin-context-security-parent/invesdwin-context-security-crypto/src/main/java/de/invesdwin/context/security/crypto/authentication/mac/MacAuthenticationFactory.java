package de.invesdwin.context.security.crypto.authentication.mac;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.AuthenticationDelegateSerde;
import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.algorithm.IMacAlgorithm;
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
    private byte[] derivedIV;

    public MacAuthenticationFactory(final byte[] key) {
        this(IMacAlgorithm.DEFAULT, key);
    }

    public MacAuthenticationFactory(final IDerivedKeyProvider derivedKeyProvider) {
        this(IMacAlgorithm.DEFAULT, derivedKeyProvider);
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
    public LayeredMacOutputStream newSignatureOutputStream(final OutputStream out) {
        return ChannelLayeredMacOutputStream.maybeWrap(out, algorithm.newMac(), key);
    }

    @Override
    public LayeredMacInputStream newVerificationInputStream(final InputStream in) {
        return ChannelLayeredMacInputStream.maybeWrap(in, algorithm.newMac(), key);
    }

    @Override
    public byte[] newSignature(final IByteBuffer src) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            return newSignature(src, mac);
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public byte[] newSignature(final IByteBuffer src, final IMac mac) {
        mac.init(key);
        mac.update(src);
        return mac.doFinal();
    }

    @Override
    public int putSignature(final IByteBuffer dest, final int destSignatureIndex) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            return putSignature(dest, destSignatureIndex, mac);
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public int putSignature(final IByteBuffer dest, final int destSignatureIndex, final IMac mac) {
        final byte[] signature = newSignature(dest.sliceTo(destSignatureIndex), mac);
        dest.putBytes(destSignatureIndex, signature);
        return signature.length;
    }

    @Override
    public int copyAndSign(final IByteBuffer src, final IByteBuffer dest) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            return copyAndSign(src, dest, mac);
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public int copyAndSign(final IByteBuffer src, final IByteBuffer dest, final IMac mac) {
        mac.init(key);
        mac.update(src);
        final byte[] signature = mac.doFinal();
        dest.putBytes(0, src);
        final int signatureIndex = src.capacity();
        dest.putBytes(signatureIndex, signature);
        return signatureIndex + signature.length;
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            return verifyAndCopy(src, dest, mac);
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public int verifyAndCopy(final IByteBuffer src, final IByteBuffer dest, final IMac mac) {
        final IByteBuffer payloadBuffer = verifyAndSlice(src, mac);
        dest.putBytes(0, payloadBuffer);
        return payloadBuffer.capacity();
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src) {
        final IMac mac = algorithm.getMacPool().borrowObject();
        try {
            return verifyAndSlice(src, mac);
        } finally {
            algorithm.getMacPool().returnObject(mac);
        }
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer src, final IMac mac) {
        mac.init(key);
        final IByteBuffer payloadBuffer = mac.verifyAndSlice(src);
        return payloadBuffer;
    }

    @SuppressWarnings("deprecation")
    @Override
    public <T> ISerde<T> maybeWrap(final ISerde<T> delegate) {
        return new AuthenticationDelegateSerde<>(delegate, this);
    }

}
