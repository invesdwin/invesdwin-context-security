package de.invesdwin.context.security.crypto.key;

import java.security.KeyPair;

public interface IDerivedKeyProvider {

    byte[] newDerivedKey(byte[] info, int length);

    KeyPair newDerivedKeyPair(String keyAlgorithm, byte[] info, int length);

}
