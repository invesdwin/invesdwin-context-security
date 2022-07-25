package de.invesdwin.context.security.crypto.encryption.cipher.wrapper;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.authentication.IAuthenticationFactory;
import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;

@NotThreadSafe
public class AuthenticatedCipher implements ICipher {

    private final ICipher cipher;
    private final IAuthenticationFactory authenticationFactory;
    private final IMac mac;

    public AuthenticatedCipher(final ICipher cipher, final IAuthenticationFactory authenticationFactory) {
        this.cipher = cipher;
        this.authenticationFactory = authenticationFactory;
        this.mac = authenticationFactory.getAlgorithm().newMac();
    }

    @Override
    public int getBlockSize() {
        return cipher.getBlockSize();
    }

    @Override
    public int getSignatureSize() {
        return cipher.getSignatureSize() + mac.getMacLength();
    }

    @Override
    public String getAlgorithm() {
        return cipher.getAlgorithm() + "With" + mac.getAlgorithm();
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) {
        cipher.init(mode, key, params);
        authenticationFactory.init(mac);
    }

    @Override
    public int update(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        cipher.update(inBuffer, outBuffer);
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        return 0;
    }

    @Override
    public int doFinal(final java.nio.ByteBuffer inBuffer, final java.nio.ByteBuffer outBuffer) {
        return 0;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output) {
        return 0;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) {
        return 0;
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        return 0;
    }

    @Override
    public byte[] doFinal() {
        return null;
    }

    @Override
    public void updateAAD(final byte aad) {
    }

    @Override
    public void updateAAD(final byte[] aad) {
    }

    @Override
    public void updateAAD(final byte[] aad, final int inputOffset, final int inputLen) {
    }

    @Override
    public void updateAAD(final java.nio.ByteBuffer aad) {
    }

    @Override
    public void close() {
    }

}
