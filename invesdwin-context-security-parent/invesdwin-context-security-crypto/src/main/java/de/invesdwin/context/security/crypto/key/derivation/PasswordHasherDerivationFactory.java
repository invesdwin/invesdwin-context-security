package de.invesdwin.context.security.crypto.key.derivation;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.util.math.Bytes;

/**
 * This is slower than the HkdfDerivationFactory.
 */
@Immutable
public class PasswordHasherDerivationFactory implements IDerivationFactory {

    public static final PasswordHasherDerivationFactory DEFAULT = new PasswordHasherDerivationFactory(
            IPasswordHasher.getDefault());

    private final IPasswordHasher passwordHasher;

    public PasswordHasherDerivationFactory(final IPasswordHasher passwordHasher) {
        this.passwordHasher = passwordHasher;
    }

    @Override
    public byte[] getPepper() {
        return passwordHasher.getPepper();
    }

    @Override
    public String getAlgorithm() {
        return passwordHasher.getAlgorithm();
    }

    @Override
    public int getExtractLength() {
        return HkdfDerivationFactory.DEFAULT.getExtractLength();
    }

    @Override
    public byte[] extract(final byte[] salt, final byte[] keyMaterial) {
        return Bytes.concat(keyMaterial, salt);
    }

    @Override
    public byte[] expand(final byte[] key, final byte[] info, final int length) {
        return passwordHasher.hash(key, info, length);
    }

}
