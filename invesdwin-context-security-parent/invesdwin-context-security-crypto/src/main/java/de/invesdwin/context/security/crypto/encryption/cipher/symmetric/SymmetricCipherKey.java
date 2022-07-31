package de.invesdwin.context.security.crypto.encryption.cipher.symmetric;

import java.security.Key;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.SecretKeySpec;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.ICipherIV;
import de.invesdwin.context.security.crypto.key.IDerivedKeyProvider;

@Immutable
public class SymmetricCipherKey implements ICipherKey {

    private final ISymmetricCipherAlgorithm algorithm;
    private final Key key;
    private final int keySize;
    private final ICipherIV cipherIV;

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider) {
        this(algorithm, derivedKeyProvider, algorithm.getDefaultKeySize());
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final IDerivedKeyProvider derivedKeyProvider,
            final int derivedKeySize) {
        this(derivedKeyProvider.newDerivedKey(algorithm,
                ("cipher-symmetric-key-" + algorithm.getKeyAlgorithm()).getBytes(), derivedKeySize));
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final byte[] derivedKey,
            final byte[] derivedIV) {
        this(algorithm, derivedKey, new CipherDerivedIV(algorithm, derivedIV));
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final byte[] key, final ICipherIV cipherIV) {
        this(algorithm, wrapKey(algorithm.getKeyAlgorithm(), key), cipherIV);
    }

    private SymmetricCipherKey(final SymmetricCipherKey symmetricKey) {
        this.algorithm = symmetricKey.algorithm;
        this.key = symmetricKey.key;
        this.keySize = symmetricKey.keySize;
        this.cipherIV = symmetricKey.cipherIV;
    }

    public SymmetricCipherKey(final ISymmetricCipherAlgorithm algorithm, final Key key, final ICipherIV cipherIV) {
        this.algorithm = algorithm;
        this.key = key;
        this.keySize = key.getEncoded().length;
        this.cipherIV = cipherIV;
    }

    @Override
    public ISymmetricCipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public Key getKey(final CipherMode mode) {
        return key;
    }

    public ICipherIV getCipherIV() {
        return cipherIV;
    }

    @Override
    public Key getEncryptKey() {
        return key;
    }

    @Override
    public Key getDecryptKey() {
        return key;
    }

    @Override
    public int getKeySize() {
        return keySize;
    }

    public static Key wrapKey(final String keyAlgorithm, final byte[] key) {
        return new SecretKeySpec(key, keyAlgorithm);
    }

    //CHECKSTYLE:OFF
    public SymmetricCipherKey withCipherIV(final ICipherIV cipherIV) {
        //CHECKSTYLE:ON
        return new SymmetricCipherKey(algorithm, key, cipherIV);
    }

}
