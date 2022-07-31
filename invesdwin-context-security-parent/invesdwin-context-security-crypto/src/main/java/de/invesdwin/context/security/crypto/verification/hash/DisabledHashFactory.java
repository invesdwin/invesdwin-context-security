package de.invesdwin.context.security.crypto.verification.hash;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.pool.IHashFactory;

@Immutable
public final class DisabledHashFactory implements IHashFactory {

    public static final DisabledHashFactory INSTANCE = new DisabledHashFactory();

    private DisabledHashFactory() {
    }

    @Override
    public IHash newHash() {
        return DisabledHash.INSTANCE;
    }

}
