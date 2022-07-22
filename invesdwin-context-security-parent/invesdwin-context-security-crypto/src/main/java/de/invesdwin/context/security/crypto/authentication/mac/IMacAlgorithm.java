package de.invesdwin.context.security.crypto.authentication.mac;

import java.security.Key;

import de.invesdwin.context.security.crypto.authentication.mac.pool.IMac;
import de.invesdwin.context.security.crypto.authentication.mac.pool.IMacFactory;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface IMacAlgorithm extends IMacFactory {

    String getAlgorithm();

    int getMacLength();

    Key wrapKey(byte[] key);

    IObjectPool<IMac> getMacPool();

}
