package de.invesdwin.context.security.crypto.encryption.verified;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class VerifiedCipherKey implements IKey {

    private static final int ENCRYPTIONKEYLENGTH_INDEX = 0;
    private static final int ENCRYPTIONKEYLENGTH_SIZE = Integer.BYTES;
    private static final int ENCRYPTIONKEY_INDEX = ENCRYPTIONKEYLENGTH_INDEX + ENCRYPTIONKEYLENGTH_SIZE;

    private final IKey encryptionKey;
    private final IKey verificationKey;

    public VerifiedCipherKey(final IKey encryptionKey, final IKey verificationKey) {
        this.encryptionKey = encryptionKey;
        this.verificationKey = verificationKey;
    }

    @Override
    public int getKeySize() {
        return encryptionKey.getKeySize();
    }

    @Override
    public int getKeyBlockSize() {
        return encryptionKey.getKeyBlockSize() + verificationKey.getKeyBlockSize();
    }

    public IKey getEncryptionKey() {
        return encryptionKey;
    }

    public IKey getVerificationKey() {
        return verificationKey;
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        int position = ENCRYPTIONKEY_INDEX;
        final int encryptionKeyLength = encryptionKey.toBuffer(buffer.sliceFrom(position));
        buffer.putInt(ENCRYPTIONKEYLENGTH_INDEX, encryptionKeyLength);
        position += encryptionKeyLength;
        final int verificationKeyLength = verificationKey.toBuffer(buffer.sliceFrom(position));
        position += verificationKeyLength;
        return position;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        final int encryptionKeyLength = buffer.getInt(ENCRYPTIONKEYLENGTH_INDEX);
        int position = ENCRYPTIONKEY_INDEX;
        final IKey encryptionKeyFromBuffer = encryptionKey.fromBuffer(buffer.slice(position, encryptionKeyLength));
        position += encryptionKeyLength;
        final IKey verificationKeyFromBuffer = verificationKey.fromBuffer(buffer.sliceFrom(position));
        return new VerifiedCipherKey(encryptionKeyFromBuffer, verificationKeyFromBuffer);
    }

    @Override
    public IKey newRandomInstance() {
        final IKey randomEncryptionKey = encryptionKey.newRandomInstance();
        final IKey randomVerificationKey = verificationKey.newRandomInstance();
        return new VerifiedCipherKey(randomEncryptionKey, randomVerificationKey);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T unwrap(final Class<T> type) {
        if (type.isAssignableFrom(getClass())) {
            return (T) this;
        } else {
            final T unwrappedEncryption = encryptionKey.unwrap(type);
            if (unwrappedEncryption != null) {
                return unwrappedEncryption;
            } else {
                return verificationKey.unwrap(type);
            }
        }
    }

}
