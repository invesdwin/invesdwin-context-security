package de.invesdwin.context.security.crypto.authentication.mac.pool;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;

public interface IMacFactory {

    String getAlgorithm();

    IMac newMac();

}
