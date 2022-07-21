package de.invesdwin.context.security.crypto.authentication.mac.pool;

import javax.annotation.concurrent.Immutable;

@Immutable
public final class DisabledMacFactory implements IMacFactory {

    public static final DisabledMacFactory INSTANCE = new DisabledMacFactory();

    private DisabledMacFactory() {
    }

    @Override
    public IMac newMac() {
        return DisabledMac.INSTANCE;
    }

}
