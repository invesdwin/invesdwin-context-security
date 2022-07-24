package de.invesdwin.context.security.crypto.authentication.mac;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.mac.pool.IMacFactory;

@Immutable
public final class DisabledMacFactory implements IMacFactory {

    public static final DisabledMacFactory INSTANCE = new DisabledMacFactory();

    private DisabledMacFactory() {
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public IMac newMac() {
        return DisabledMac.INSTANCE;
    }

}
