package de.invesdwin.context.security.crypto.authentication.mac.pool;

import java.security.Key;

public interface IMac {

    String getAlgorithm();

    int getMacLength();

    /**
     * This will skip init if the same key is used and do a reset instead if needed
     */
    void init(Key key);

    void update(java.nio.ByteBuffer input);

    void update(byte input);

    void update(byte[] input);

    void update(byte[] input, int inputOffset, int inputLen);

    byte[] doFinal();

    byte[] doFinal(byte[] input);

    void doFinal(byte[] output, int offset);

    /**
     * Will only reset if needed (pending update data without a reset, doFinal or init call afterwards)
     */
    void reset();

}
