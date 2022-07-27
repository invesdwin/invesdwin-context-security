package de.invesdwin.context.security.crypto.verification.hash.pool;

import de.invesdwin.context.security.crypto.verification.hash.IHash;

public interface IHashFactory {

    String getAlgorithm();

    IHash newHash();

}
