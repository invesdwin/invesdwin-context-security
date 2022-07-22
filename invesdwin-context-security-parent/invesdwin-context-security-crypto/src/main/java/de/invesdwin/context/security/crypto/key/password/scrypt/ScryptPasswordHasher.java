package de.invesdwin.context.security.crypto.key.password.scrypt;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.math.Bytes;

@Immutable
public class ScryptPasswordHasher implements IPasswordHasher {

    public static final ScryptPasswordHasher INSTANCE = new ScryptPasswordHasher();

    private final byte[] pepper;
    private final FastScryptFunction scrypt;

    private ScryptPasswordHasher() {
        this(CryptoProperties.DEFAULT_PEPPER);
    }

    public ScryptPasswordHasher(final byte[] pepper) {
        this(pepper, FastScryptFunction.INSTANCE);
    }

    public ScryptPasswordHasher(final byte[] pepper, final FastScryptFunction scrypt) {
        this.pepper = pepper;
        this.scrypt = scrypt;
    }

    @Override
    public byte[] getPepper() {
        return pepper;
    }

    @Override
    public String getAlgorithm() {
        return "Scrypt";
    }

    public FastScryptFunction getScrypt() {
        return scrypt;
    }

    @Override
    public byte[] hash(final byte[] salt, final byte[] password, final int length) {
        return scrypt.scrypt(password, Bytes.concat(salt, pepper), length);
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                .add("workFactor", scrypt.getWorkFactor())
                .add("resources", scrypt.getResources())
                .add("parallelization", scrypt.getParallelization())
                .toString();
    }

}
