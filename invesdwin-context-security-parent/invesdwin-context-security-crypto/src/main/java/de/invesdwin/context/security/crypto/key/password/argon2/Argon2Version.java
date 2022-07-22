package de.invesdwin.context.security.crypto.key.password.argon2;

import javax.annotation.concurrent.Immutable;

import org.bouncycastle.crypto.params.Argon2Parameters;

import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;

@Immutable
public enum Argon2Version {
    _10(Argon2Parameters.ARGON2_VERSION_10, de.mkammerer.argon2.Argon2Version.V10),
    _13(Argon2Parameters.ARGON2_VERSION_13, de.mkammerer.argon2.Argon2Version.V13);

    public static final Argon2Version DEFAULT = _13;
    private static final Int2ObjectOpenHashMap<Argon2Version> VERSION_MAP = new Int2ObjectOpenHashMap<>();

    static {
        for (final Argon2Version version : values()) {
            VERSION_MAP.put(version.getVersion(), version);
        }
    }

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

    public static Argon2Version valueOfVersion(final int version) {
        return VERSION_MAP.get(version);
    }
}
