package de.invesdwin.context.security.crypto.encryption.verified;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IKey;

@Immutable
public class VerifiedCipherKey implements IKey {

    private final IKey encryptionKey;
    private final IKey verificationKey;

    public VerifiedCipherKey(final IKey encryptionKey, final IKey verificationKey) {
        this.encryptionKey = encryptionKey;
        this.verificationKey = verificationKey;
    }

    @Override
    public int getKeySize() {
        return encryptionKey.getKeySize() + verificationKey.getKeySize();
    }

    public IKey getEncryptionKey() {
        return encryptionKey;
    }

    public IKey getVerificationKey() {
        return verificationKey;
    }

}
