package de.invesdwin.context.security.crypto.authentication.mac.algorithm;

import java.security.Key;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.authentication.mac.pool.IMacFactory;
import de.invesdwin.util.concurrent.pool.IObjectPool;

public interface IMacAlgorithm extends IMacFactory {

    IMacAlgorithm DEFAULT = HmacAlgorithm.DEFAULT;

    int getMacLength();

    Key wrapKey(byte[] key);

    IObjectPool<IMac> getMacPool();

}
