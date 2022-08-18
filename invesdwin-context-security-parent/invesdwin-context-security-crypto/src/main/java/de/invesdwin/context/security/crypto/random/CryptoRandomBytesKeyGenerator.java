package de.invesdwin.context.security.crypto.random;

import javax.annotation.concurrent.Immutable;

import org.springframework.security.crypto.keygen.BytesKeyGenerator;

@Immutable
public class CryptoRandomBytesKeyGenerator implements BytesKeyGenerator {

    private final int keyLength;

    public CryptoRandomBytesKeyGenerator(final int keyLength) {
        this.keyLength = keyLength;
    }

    @Override
    public int getKeyLength() {
        return keyLength;
    }

    @Override
    public byte[] generateKey() {
        final CryptoRandomGenerator random = CryptoRandomGenerators.getThreadLocalCryptoRandom();
        final byte[] key = new byte[keyLength];
        random.nextBytes(key);
        return key;
    }

}
