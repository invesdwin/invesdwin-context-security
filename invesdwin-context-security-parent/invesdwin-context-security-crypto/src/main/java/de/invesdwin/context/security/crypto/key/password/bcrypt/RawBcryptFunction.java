package de.invesdwin.context.security.crypto.key.password.bcrypt;

import java.util.Arrays;

import javax.annotation.concurrent.NotThreadSafe;

import com.password4j.BadParametersException;
import com.password4j.BcryptFunction;
import com.password4j.types.Bcrypt;

import de.invesdwin.util.math.Bytes;

@NotThreadSafe
public class RawBcryptFunction extends BcryptFunction {

    public static final Bcrypt DEFAULT_BCRYPT_TYPE = Bcrypt.B;
    public static final int DEFAULT_BCRYPT_LOG_ROUNDS = 10;
    public static final int BCRYPT_SALT_LENGTH = 16;

    public static final RawBcryptFunction INSTANCE = new RawBcryptFunction();

    private final boolean addNullTerminator;
    private final boolean sign;
    private final int safety;

    public RawBcryptFunction() {
        this(DEFAULT_BCRYPT_LOG_ROUNDS);
    }

    public RawBcryptFunction(final int logRounds) {
        this(DEFAULT_BCRYPT_TYPE, logRounds);
    }

    public RawBcryptFunction(final Bcrypt type, final int logRounds) {
        super(type, logRounds);
        this.addNullTerminator = getType().minor() >= Bcrypt.A.minor();
        this.sign = getType() == Bcrypt.X;
        this.safety = getType() == Bcrypt.A ? 0x10000 : 0;
    }

    public byte[] cryptRaw(final byte[] password, final byte[] salt) {
        final byte[] passwordb;
        if (addNullTerminator) {
            passwordb = Arrays.copyOf(password, password.length + 1);
        } else {
            passwordb = password;
        }
        final byte[] saltb;
        if (salt.length == BCRYPT_SALT_LENGTH) {
            saltb = salt;
        } else if (salt.length > BCRYPT_SALT_LENGTH) {
            saltb = Bytes.subArrayLength(salt, 0, BCRYPT_SALT_LENGTH);
        } else {
            throw new BadParametersException(
                    "A salt length of at least " + BCRYPT_SALT_LENGTH + " is required: " + salt.length);
        }

        return cryptRaw(passwordb, saltb, getLogarithmicRounds(), sign, safety);
    }

}
