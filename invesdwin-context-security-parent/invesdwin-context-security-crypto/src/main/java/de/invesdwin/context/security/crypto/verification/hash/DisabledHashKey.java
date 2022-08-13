package de.invesdwin.context.security.crypto.verification.hash;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@Immutable
public class DisabledHashKey implements IHashKey {

    public static final DisabledHashKey INSTANCE = new DisabledHashKey();

    @Override
    public int getKeySizeBits() {
        return 0;
    }

    @Override
    public int getKeyBlockSize() {
        return 0;
    }

    @Override
    public int toBuffer(final IByteBuffer buffer) {
        return 0;
    }

    @Override
    public IKey fromBuffer(final IByteBuffer buffer) {
        return this;
    }

    @Override
    public IKey newRandomInstance() {
        return this;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T unwrap(final Class<T> type) {
        if (type.isAssignableFrom(getClass())) {
            return (T) this;
        } else {
            return null;
        }
    }

    @Override
    public IHashAlgorithm getAlgorithm() {
        return null;
    }

    @Override
    public Key getSignKey() {
        return null;
    }

    @Override
    public Key getVerifyKey() {
        return null;
    }

}
