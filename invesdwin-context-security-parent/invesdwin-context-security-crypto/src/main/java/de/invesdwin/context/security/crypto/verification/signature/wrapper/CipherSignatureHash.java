package de.invesdwin.context.security.crypto.verification.signature.wrapper;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricEncryptionFactory;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.SignatureCipherKey;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.DisabledHashKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.signature.SignatureKey;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class CipherSignatureHash implements IHash {

    private final IHash hash;
    private final AsymmetricEncryptionFactory encryptionFactory;
    private final ICipher cipher;
    private final IByteBuffer encryptedHashBuffer = ByteBuffers.allocateExpandable();

    private HashMode prevMode;
    private IKey prevKey;

    public CipherSignatureHash(final IHash hash, final AsymmetricEncryptionFactory encryptionFactory) {
        this.hash = hash;
        this.encryptionFactory = encryptionFactory;
        this.cipher = encryptionFactory.getAlgorithm().newCipher();
    }

    @Override
    public String getAlgorithm() {
        return hash.getAlgorithm() + "with" + cipher.getAlgorithm();
    }

    @Override
    public boolean isDynamicHashSize() {
        return true;
    }

    @Override
    public int getHashSize() {
        return IHashAlgorithm.DYNAMIC_HASH_SIZE;
    }

    @Override
    public void init(final HashMode mode, final IKey key) {
        final SignatureKey cKey = (SignatureKey) key;
        hash.init(mode, DisabledHashKey.INSTANCE);
        encryptionFactory.init(mode.getCipherMode(), cipher, new SignatureCipherKey(encryptionFactory.getAlgorithm(),
                cKey.getVerifyKey(), cKey.getSignKey(), cKey.getKeySizeBits()), null);
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        hash.update(input);
    }

    @Override
    public void update(final byte input) {
        hash.update(input);
    }

    @Override
    public void update(final byte[] input) {
        hash.update(input);
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        hash.update(input, inputOffset, inputLen);
    }

    @Override
    public byte[] doFinal() {
        final byte[] toBeEncrypted = hash.doFinal();
        final int encryptedSize = cipher.doFinal(ByteBuffers.wrap(toBeEncrypted), encryptedHashBuffer);
        encryptedHashBuffer.putInt(encryptedSize, encryptedSize);
        return encryptedHashBuffer.asByteArrayCopyTo(encryptedSize + Integer.BYTES);
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        final byte[] toBeEncrypted = hash.doFinal(input);
        final int encryptedSize = cipher.doFinal(ByteBuffers.wrap(toBeEncrypted), encryptedHashBuffer);
        encryptedHashBuffer.putInt(encryptedSize, encryptedSize);
        return encryptedHashBuffer.asByteArrayCopyTo(encryptedSize + Integer.BYTES);
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        final byte[] toBeEncrypted = hash.doFinal();
        final int encryptedSize = cipher.doFinal(ByteBuffers.wrap(toBeEncrypted), encryptedHashBuffer);
        encryptedHashBuffer.putInt(encryptedSize, encryptedSize);
        encryptedHashBuffer.getBytes(0, output, offset, encryptedSize + Integer.BYTES);
        return encryptedSize;
    }

    @Override
    public void reset() {
        init(prevMode, prevKey);
    }

    @Override
    public void close() {
        prevMode = null;
        prevKey = null;
    }

    @Override
    public boolean verify(final byte[] signedInput) {
        return IHash.super.verify(signedInput);
    }

    @Override
    public IByteBuffer verifyAndSlice(final IByteBuffer signedInput) {
        return IHash.super.verifyAndSlice(signedInput);
    }

    @Override
    public void verifyThrow(final IByteBuffer signedInput) {
        IHash.super.verifyThrow(signedInput);
    }

    @Override
    public boolean verify(final IByteBuffer signedInput) {
        return IHash.super.verify(signedInput);
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        update(input);
        final byte[] calculatedSignature = doFinal();
        return ByteBuffers.constantTimeEquals(signature, calculatedSignature);
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        update(input);
        final byte[] calculatedSignature = doFinal();
        return ByteBuffers.constantTimeEquals(signature, calculatedSignature);
    }

}
