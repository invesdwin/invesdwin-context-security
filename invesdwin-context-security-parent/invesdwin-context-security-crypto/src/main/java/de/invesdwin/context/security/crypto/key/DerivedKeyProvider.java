package de.invesdwin.context.security.crypto.key;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricCipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricCipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.iv.CipherDerivedIV;
import de.invesdwin.context.security.crypto.key.derivation.IDerivationFactory;
import de.invesdwin.context.security.crypto.key.password.IPasswordHasher;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerator;
import de.invesdwin.context.security.crypto.random.CryptoRandomGenerators;
import de.invesdwin.context.security.crypto.verification.hash.HashKey;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.signature.SignatureKey;
import de.invesdwin.context.security.crypto.verification.signature.algorithm.ISignatureAlgorithm;

/**
 * Key derivation techniques are: Password+PBKDF2+HKDFexpands or Random+HKDFextract+HKDFexpands
 * 
 * We can derive AES-KEY, AES-IV, MAC-KEY from the initial Password or Random. scrypt and bcrypt are alternatives to
 * PBKDF2
 * 
 * The salt should be a random value always that can be publicly exchanged before deriving additional passwords. The
 * password or random value should be transmitted over a secure channel or pre-shared. Though if a secure channel is
 * used anyhow, then it is best to transmit the salt and the key together over the secure channel. Using a null or fixed
 * salt is less secure.
 * 
 * https://security.stackexchange.com/questions/48000/why-would-you-need-a-salt-for-aes-cbs-when-iv-is-already-randomly-generated-and
 */
@Immutable
public class DerivedKeyProvider implements IDerivedKeyProvider {

    private final IDerivationFactory derivationFactory;
    private final byte[] key;

    public DerivedKeyProvider(final byte[] key, final IDerivationFactory derivationFactory) {
        this.key = key;
        this.derivationFactory = derivationFactory;
    }

    @Override
    public byte[] newDerivedKey(final byte[] info, final int sizeBits) {
        int sizeBytes = sizeBits / Byte.SIZE;
        if (sizeBits % Byte.SIZE != 0) {
            //add a bit more entropy for a random seed
            sizeBytes++;
        }
        return derivationFactory.expand(key, info, sizeBytes);
    }

    @Override
    public SymmetricCipherKey newDerivedKey(final ISymmetricCipherAlgorithm algorithm, final byte[] info,
            final int sizeBits) {
        return new SymmetricCipherKey(algorithm, newDerivedKey(info, sizeBits), new CipherDerivedIV(algorithm, this));
    }

    @Override
    public HashKey newDerivedKey(final IHashAlgorithm algorithm, final byte[] info, final int sizeBits) {
        return new HashKey(algorithm, newDerivedKey(info, sizeBits));
    }

    @Override
    public AsymmetricCipherKey newDerivedKey(final IAsymmetricCipherAlgorithm algorithm, final byte[] info,
            final int sizeBits) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.getKeyAlgorithm());
            //we need a deterministic pseudorandom seed
            final byte[] seed = newDerivedKey(info, sizeBits);
            //we need to use a pseudorandom generator in order to be able to seed it
            final CryptoRandomGenerator random = CryptoRandomGenerators.newCryptoRandom(seed);
            generator.initialize(sizeBits, random);
            final KeyPair keyPair = generator.generateKeyPair();
            return new AsymmetricCipherKey(algorithm, keyPair, sizeBits);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SignatureKey newDerivedKey(final ISignatureAlgorithm algorithm, final byte[] info, final int sizeBits) {
        try {
            final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.getKeyAlgorithm());
            //we need a deterministic pseudorandom seed
            final byte[] seed = newDerivedKey(info, sizeBits);
            //we need to use a pseudorandom generator in order to be able to seed it
            final CryptoRandomGenerator random = CryptoRandomGenerators.newCryptoRandom(seed);
            generator.initialize(sizeBits, random);
            final KeyPair keyPair = generator.generateKeyPair();
            return new SignatureKey(algorithm, keyPair, sizeBits);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static DerivedKeyProvider fromPassword(final byte[] salt, final String password) {
        return fromPassword(salt, password, IDerivationFactory.getDefault(), IPasswordHasher.getDefault());
    }

    public static DerivedKeyProvider fromPassword(final byte[] salt, final byte[] password) {
        return fromPassword(salt, password, IDerivationFactory.getDefault(), IPasswordHasher.getDefault());
    }

    public static DerivedKeyProvider fromRandom(final byte[] salt, final byte[] random) {
        return fromRandom(salt, random, IDerivationFactory.getDefault());
    }

    public static DerivedKeyProvider fromPassword(final byte[] salt, final String password,
            final IDerivationFactory derivationFactory, final IPasswordHasher passwordHasher) {
        return fromPassword(salt, password.getBytes(), derivationFactory, passwordHasher);
    }

    public static DerivedKeyProvider fromPassword(final byte[] salt, final byte[] password,
            final IDerivationFactory derivationFactory, final IPasswordHasher passwordHasher) {
        final byte[] key = passwordHasher.hash(salt, password, derivationFactory.getExtractLength());
        return new DerivedKeyProvider(key, derivationFactory);
    }

    public static DerivedKeyProvider fromRandom(final byte[] salt, final byte[] random,
            final IDerivationFactory derivationFactory) {
        final byte[] key = derivationFactory.extract(salt, random);
        return new DerivedKeyProvider(key, derivationFactory);
    }

}
