package de.invesdwin.context.security.crypto.verification.signature.algorithm;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HashAlgorithmType;
import de.invesdwin.context.security.crypto.verification.hash.pool.HashObjectPool;
import de.invesdwin.context.security.crypto.verification.hash.wrapper.LazyDelegateHash;
import de.invesdwin.context.security.crypto.verification.signature.wrapper.JceSignatureHash;
import de.invesdwin.util.concurrent.pool.IObjectPool;

/**
 * https://cryptobook.nakov.com/digital-signatures/eddsa-and-ed25519
 */
@Immutable
public enum EddsaAlgorithm implements ISignatureAlgorithm {
    /**
     * https://paretosecurity.com/auditor/checks/ssh-keys-strength
     * 
     * https://winscp.net/eng/docs/ui_puttygen (255 is the actual key size, 256 is accepted for backwards compatibility)
     */
    Ed25519("Ed25519", "Ed25519", 255, 64),
    /**
     * should be 50% as slower than Ed25519
     * 
     * https://crypto.stackexchange.com/questions/67457/elliptic-curve-ed25519-vs-ed448-differences
     */
    Ed448("Ed448", "Ed448", 448, 114);

    /**
     * Recommended by: https://goteleport.com/blog/comparing-ssh-keys/
     */
    public static final EddsaAlgorithm DEFAULT = Ed25519;

    private final String algorithm;
    private final String keyAlgorithm;
    private final int defaultKeySizeBits;
    private final int hashSize;
    private final HashObjectPool hashPool;

    EddsaAlgorithm(final String algorithm, final String keyAlgorithm, final int defaultKeySizeBits,
            final int hashSize) {
        this.algorithm = algorithm;
        this.keyAlgorithm = keyAlgorithm;
        this.defaultKeySizeBits = defaultKeySizeBits;
        this.hashSize = hashSize;
        this.hashPool = new HashObjectPool(this);
    }

    @Override
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getDefaultKeySizeBits() {
        return defaultKeySizeBits;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public boolean isDynamicHashSize() {
        return false;
    }

    @Override
    public HashAlgorithmType getType() {
        return HashAlgorithmType.Signature;
    }

    @Override
    public IObjectPool<IHash> getHashPool() {
        return hashPool;
    }

    @Override
    public IHash newHash() {
        return new LazyDelegateHash(new JceSignatureHash(algorithm, hashSize));
    }

}
