package de.invesdwin.context.security.crypto.key;

public interface IDerivedKeyProvider {

    byte[] getKey();

    byte[] getSalt();

    byte[] newDerivedKey(byte[] info, int length);

}
