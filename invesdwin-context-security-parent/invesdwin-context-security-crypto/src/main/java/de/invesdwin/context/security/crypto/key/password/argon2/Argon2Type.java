package de.invesdwin.context.security.crypto.key.password.argon2;

import javax.annotation.concurrent.Immutable;

import org.bouncycastle.crypto.params.Argon2Parameters;

import com.password4j.types.Argon2;

import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import it.unimi.dsi.fastutil.ints.Int2ObjectOpenHashMap;

@Immutable
public enum Argon2Type {
    d(Argon2Parameters.ARGON2_d, Argon2Types.ARGON2id, Argon2.D),
    i(Argon2Parameters.ARGON2_i, Argon2Types.ARGON2i, Argon2.I),
    id(Argon2Parameters.ARGON2_id, Argon2Types.ARGON2id, Argon2.ID);

    public static final Argon2Type DEFAULT = id;

    private static final Int2ObjectOpenHashMap<Argon2Type> TYPE_MAP = new Int2ObjectOpenHashMap<>();

    static {
        for (final Argon2Type type : values()) {
            TYPE_MAP.put(type.getType(), type);
        }
    }

    private int type;
    private Argon2Types nativeType;
    private Argon2 jvmType;

    Argon2Type(final int type, final Argon2Types nativeType, final Argon2 jvmType) {
        this.type = type;
        this.nativeType = nativeType;
        this.jvmType = jvmType;
    }

    public int getType() {
        return type;
    }

    public Argon2Types getNativeType() {
        return nativeType;
    }

    public Argon2 getJvmType() {
        return jvmType;
    }

    public static Argon2Type valueOfType(final int type) {
        return TYPE_MAP.get(type);
    }
}
