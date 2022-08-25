package de.invesdwin.context.security.crypto.key.password;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.key.derivation.HkdfDerivationFactory;
import de.invesdwin.context.security.crypto.key.derivation.IDerivationFactory;
import de.invesdwin.context.security.crypto.key.password.pbkdf2.Pbkdf2PasswordHasher;
import de.invesdwin.context.security.crypto.verification.hash.HashKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.math.Bytes;

@Immutable
public class SimplePasswordHasher implements IPasswordHasher {

    public static final SimplePasswordHasher DEFAULT = new SimplePasswordHasher();

    private final byte[] pepper;
    private final IHashAlgorithm hashAlgorithm;
    private final HashKey hashKey;

    private SimplePasswordHasher() {
        this(CryptoProperties.DEFAULT_PEPPER);
    }

    public SimplePasswordHasher(final byte[] pepper) {
        this(pepper, Pbkdf2PasswordHasher.DEFAULT_HASH_ALGORITHM);
    }

    public SimplePasswordHasher(final byte[] pepper, final IHashAlgorithm hashAlgorithm) {
        this.pepper = pepper;
        this.hashAlgorithm = hashAlgorithm;
        this.hashKey = new HashKey(hashAlgorithm, pepper);
    }

    @Override
    public byte[] getPepper() {
        return pepper;
    }

    @Override
    public String getAlgorithm() {
        return hashAlgorithm.getAlgorithm();
    }

    @Override
    public int getDefaultHashLength() {
        return hashAlgorithm.getHashSize();
    }

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        final IHash hash = hashAlgorithm.getHashPool().borrowObject();
        try {
            hash.init(HashMode.Sign, hashKey);
            final byte[] hashed = hash.doFinal(Bytes.concat(salt, password));

            if (hashed.length == length) {
                return hashed;
            }
            //make sure we generate the desired number of bytes for key derivation
            final IDerivationFactory derivationFactory = getDerivationFactory();
            final byte[] extracted = derivationFactory.extract(salt, hashed);
            if (extracted.length == length) {
                return extracted;
            }
            final byte[] expanded = derivationFactory.expand(extracted, Bytes.EMPTY_ARRAY, length);
            return expanded;
        } finally {
            hashAlgorithm.getHashPool().returnObject(hash);
        }
    }

    protected IDerivationFactory getDerivationFactory() {
        return HkdfDerivationFactory.DEFAULT;
    }

}
