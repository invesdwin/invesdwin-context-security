package de.invesdwin.context.security.crypto.verification.hash;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.util.error.UnknownArgumentException;

@Immutable
public enum HashMode {
    Sign {
        @Override
        public Key getKey(final IHashKey key) {
            return key.getSignKey();
        }

        @Override
        public CipherMode getCipherMode() {
            return CipherMode.Encrypt;
        }
    },
    Verify {
        @Override
        public Key getKey(final IHashKey key) {
            return key.getVerifyKey();
        }

        @Override
        public CipherMode getCipherMode() {
            return CipherMode.Decrypt;
        }
    };

    public abstract Key getKey(IHashKey key);

    public static HashMode valueOf(final CipherMode cipherMode) {
        switch (cipherMode) {
        case Encrypt:
            return Sign;
        case Decrypt:
            return Verify;
        default:
            throw UnknownArgumentException.newInstance(CipherMode.class, cipherMode);
        }
    }

    public abstract CipherMode getCipherMode();

}
