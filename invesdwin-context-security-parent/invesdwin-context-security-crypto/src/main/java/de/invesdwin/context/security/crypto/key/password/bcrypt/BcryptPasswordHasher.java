package de.invesdwin.context.security.crypto.key.password.bcrypt;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.key.derivation.HkdfDerivationFactory;
import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.math.Bytes;

/**
 * Bcrypt only produces a raw hash of 24 bytes. We use HKDF to make it the desired length.
 */
@Immutable
public class BcryptPasswordHasher implements IPasswordHasher {

    public static final int BCRYPT_HASH_LENGTH = 24;

    public static final BcryptPasswordHasher INSTANCE = new BcryptPasswordHasher();

    private final RawBcryptFunction bcrypt;
    private final byte[] pepper;

    private BcryptPasswordHasher() {
        this(CryptoProperties.DEFAULT_PEPPER);
    }

    public BcryptPasswordHasher(final byte[] pepper) {
        this(pepper, RawBcryptFunction.INSTANCE);
    }

    public BcryptPasswordHasher(final byte[] pepper, final RawBcryptFunction bcrypt) {
        this.pepper = pepper;
        this.bcrypt = bcrypt;
    }

    @Override
    public byte[] getPepper() {
        return pepper;
    }

    public RawBcryptFunction getBcrypt() {
        return bcrypt;
    }

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        final byte[] hashed = bcrypt.cryptRaw(password, Bytes.concat(salt, pepper));

        assert hashed.length == BCRYPT_HASH_LENGTH : "Expecting " + BCRYPT_HASH_LENGTH
                + " hash length from bcrypt but got: " + hashed.length;

        if (hashed.length == length) {
            return hashed;
        }
        //make sure we generate the desired number of bytes for key derivation
        final byte[] extracted = HkdfDerivationFactory.INSTANCE.extract(salt, hashed);
        if (extracted.length == length) {
            return extracted;
        }
        final byte[] expanded = HkdfDerivationFactory.INSTANCE.expand(extracted, Bytes.EMPTY_ARRAY, length);
        return expanded;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                .add("type", bcrypt.getType())
                .add("logRounds", bcrypt.getLogarithmicRounds())
                .toString();
    }

}
