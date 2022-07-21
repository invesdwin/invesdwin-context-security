package de.invesdwin.context.security.crypto.authentication.mac.pool;

import javax.annotation.concurrent.Immutable;

@Immutable
public class JceMacFactory implements IMacFactory {

    private final String algorithm;

    public JceMacFactory(final String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public IMac newMac() {
        return new JceMac(algorithm);
    }

}
