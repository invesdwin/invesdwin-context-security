package de.invesdwin.context.security.crypto.key;

import de.invesdwin.context.security.crypto.encryption.cipher.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.AsymmetricCipherKey;
import de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.IAsymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.ISymmetricCipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.symmetric.SymmetricCipherKey;
import de.invesdwin.context.security.crypto.verification.hash.HashKey;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.signature.SignatureKey;
import de.invesdwin.context.security.crypto.verification.signature.algorithm.ISignatureAlgorithm;
import de.invesdwin.util.error.UnknownArgumentException;

public interface IDerivedKeyProvider {

    byte[] newDerivedKey(byte[] info, int sizeBits);

    default IKey newDerivedKey(final ICipherAlgorithm algorithm, final byte[] info, final int sizeBits) {
        if (algorithm instanceof ISymmetricCipherAlgorithm) {
            final ISymmetricCipherAlgorithm cAlgorithm = (ISymmetricCipherAlgorithm) algorithm;
            return newDerivedKey(cAlgorithm, info, sizeBits);
        } else if (algorithm instanceof IAsymmetricCipherAlgorithm) {
            final IAsymmetricCipherAlgorithm cAlgorithm = (IAsymmetricCipherAlgorithm) algorithm;
            return newDerivedKey(cAlgorithm, info, sizeBits);
        } else {
            throw UnknownArgumentException.newInstance(ICipherAlgorithm.class, algorithm);
        }
    }

    SymmetricCipherKey newDerivedKey(ISymmetricCipherAlgorithm algorithm, byte[] info, int sizeBits);

    AsymmetricCipherKey newDerivedKey(IAsymmetricCipherAlgorithm algorithm, byte[] info, int sizeBits);

    HashKey newDerivedKey(IHashAlgorithm algorithm, byte[] info, int sizeBits);

    SignatureKey newDerivedKey(ISignatureAlgorithm algorithm, byte[] info, int sizeBits);

}
