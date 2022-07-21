package de.invesdwin.context.security.crypto.key;

public interface IDerivedKeyProvider {

    byte[] newDerivedKey(byte[] info, int length);

}
