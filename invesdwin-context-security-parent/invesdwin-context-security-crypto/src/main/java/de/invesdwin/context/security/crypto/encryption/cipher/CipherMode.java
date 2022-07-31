package de.invesdwin.context.security.crypto.encryption.cipher;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.Cipher;

import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.util.error.UnknownArgumentException;

/**
 * The pointer dereferencing of this enum (during cipher.init) should not fall into weight in comparison to the heavy
 * lifting of the actual encryption/decryption.
 */
@Immutable
public enum CipherMode {
    Encrypt(Cipher.ENCRYPT_MODE) {
        @Override
        public Key getKey(final ICipherKey key) {
            return key.getEncryptKey();
        }
    },
    Decrypt(Cipher.DECRYPT_MODE) {
        @Override
        public Key getKey(final ICipherKey key) {
            return key.getDecryptKey();
        }
    };

    private int jceMode;

    CipherMode(final int jceMode) {
        this.jceMode = jceMode;
    }

    public int getJceMode() {
        return jceMode;
    }

    public abstract Key getKey(ICipherKey key);

    public HashMode getHashMode() {
        return HashMode.valueOf(this);
    }

    public static CipherMode valueOf(final HashMode hashMode) {
        switch (hashMode) {
        case Sign:
            return Encrypt;
        case Verify:
            return Decrypt;
        default:
            throw UnknownArgumentException.newInstance(HashMode.class, hashMode);
        }
    }

}
