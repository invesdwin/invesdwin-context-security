package de.invesdwin.context.security.crypto.key.password.argon2;

import javax.annotation.concurrent.Immutable;

import org.bouncycastle.crypto.params.Argon2Parameters;

@Immutable
public enum Argon2Version {
    _10(Argon2Parameters.ARGON2_VERSION_10, de.mkammerer.argon2.Argon2Version.V10),
    _13(Argon2Parameters.ARGON2_VERSION_13, de.mkammerer.argon2.Argon2Version.V13);

    public static final Argon2Version DEFAULT = _13;

    private int version;

    private de.mkammerer.argon2.Argon2Version nativeVersion;

    Argon2Version(final int version, final de.mkammerer.argon2.Argon2Version nativeVersion) {
        this.version = version;
        this.nativeVersion = nativeVersion;
    }

    public int getVersion() {
        return version;
    }

    public de.mkammerer.argon2.Argon2Version getNativeVersion() {
        return nativeVersion;
    }
}
