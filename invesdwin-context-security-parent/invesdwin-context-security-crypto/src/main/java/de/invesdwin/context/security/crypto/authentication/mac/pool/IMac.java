package de.invesdwin.context.security.crypto.authentication.mac.pool;

import java.security.Key;

public interface IMac {

    String getAlgorithm();

    int getMacLength();

    void init(Key key);

    void update(java.nio.ByteBuffer input);

    void update(byte input);

    void update(byte[] input);

    void update(byte[] input, int inputOffset, int inputLen);

    byte[] doFinal();

    byte[] doFinal(byte[] input);

    void doFinal(byte[] output, int offset);

}
