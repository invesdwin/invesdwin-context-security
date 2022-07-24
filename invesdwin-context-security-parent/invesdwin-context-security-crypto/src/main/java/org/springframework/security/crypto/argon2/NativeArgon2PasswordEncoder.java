package org.springframework.security.crypto.argon2;

import javax.annotation.concurrent.Immutable;

import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;

import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Type;
import de.invesdwin.context.security.crypto.key.password.argon2.Argon2Version;
import de.invesdwin.context.security.crypto.key.password.argon2.IArgon2PasswordHasher;
import de.invesdwin.context.security.crypto.random.CryptoRandomBytesKeyGenerator;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;

@Immutable
public class NativeArgon2PasswordEncoder implements PasswordEncoder {

    public static final NativeArgon2PasswordEncoder INSTANCE = new NativeArgon2PasswordEncoder();

    private static final int DEFAULT_SALT_LENGTH = 16;
    private static final int DEFAULT_HASH_LENGTH = 32;

    private final org.apache.commons.logging.Log logger = org.apache.commons.logging.LogFactory.getLog(getClass());
    private final int hashLength;
    private final BytesKeyGenerator saltGenerator;
    private final IArgon2PasswordHasher argon2;

    private NativeArgon2PasswordEncoder() {
        this(IArgon2PasswordHasher.INSTANCE);
    }

    public NativeArgon2PasswordEncoder(final IArgon2PasswordHasher argon2) {
        this(argon2, DEFAULT_SALT_LENGTH, DEFAULT_HASH_LENGTH);
    }

    /**
     * Using interface here so that we can gracefully fallback to a jvm version if native is unsupported.
     */
    public NativeArgon2PasswordEncoder(final IArgon2PasswordHasher argon2, final int saltLength, final int hashLength) {
        this.hashLength = hashLength;
        this.argon2 = argon2;
        this.saltGenerator = new CryptoRandomBytesKeyGenerator(saltLength);
    }

    @Override
    public String encode(final CharSequence rawPassword) {
        final byte[] salt = this.saltGenerator.generateKey();
        final byte[] hash = new byte[this.hashLength];
        final Argon2Parameters params = new Argon2Parameters.Builder(argon2.getType().getType()).withSalt(salt)
                .withParallelism(argon2.getParallelism())
                .withMemoryAsKB(argon2.getMemory())
                .withIterations(argon2.getIterations())
                .withVersion(argon2.getVersion().getVersion())
                .build();
        argon2.hash(salt, Bytes.fromCharSequenceToBytes(rawPassword), hashLength);
        return Argon2EncodingUtils.encode(hash, params);
    }

    @Override
    public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
        if (encodedPassword == null) {
            this.logger.warn("password hash is null");
            return false;
        }
        final Argon2EncodingUtils.Argon2Hash decoded;
        try {
            decoded = Argon2EncodingUtils.decode(encodedPassword);
        } catch (final IllegalArgumentException ex) {
            this.logger.warn("Malformed password hash", ex);
            return false;
        }
        final Argon2Parameters parameters = decoded.getParameters();
        final IArgon2PasswordHasher decodedArgon2 = argon2.getFactory()
                .newInstance(argon2.getPepper(), Argon2Type.valueOfType(parameters.getType()),
                        Argon2Version.valueOfVersion(parameters.getVersion()), parameters.getMemory(),
                        parameters.getIterations(), parameters.getLanes());
        final byte[] hashBytes = decodedArgon2.hash(parameters.getSalt(), Bytes.fromCharSequenceToBytes(rawPassword),
                decoded.getHash().length);
        return ByteBuffers.constantTimeEquals(decoded.getHash(), hashBytes);
    }

    @Override
    public boolean upgradeEncoding(final String encodedPassword) {
        if (encodedPassword == null || encodedPassword.length() == 0) {
            this.logger.warn("password hash is null");
            return false;
        }
        final Argon2Parameters parameters = Argon2EncodingUtils.decode(encodedPassword).getParameters();
        return parameters.getMemory() < argon2.getMemory() || parameters.getIterations() < argon2.getIterations();
    }

}
