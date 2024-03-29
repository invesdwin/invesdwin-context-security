package de.invesdwin.context.security.crypto.key.derivation;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.verification.hash.HashKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.hmac.HmacAlgorithm;
import de.invesdwin.util.math.Bytes;
import de.invesdwin.util.math.Integers;

/**
 * Adapted from: https://github.com/NetRiceCake/HKDF/blob/master/src/main/java/com/github/netricecake/hkdf/HKDF.java
 */
@Immutable
public class HkdfDerivationFactory implements IDerivationFactory {

    public static final HkdfDerivationFactory DEFAULT = new HkdfDerivationFactory();

    private final byte[] pepper;
    private final IHashAlgorithm algorithm;

    private HkdfDerivationFactory() {
        this(CryptoProperties.DEFAULT_PEPPER, HmacAlgorithm.DEFAULT);
    }

    public HkdfDerivationFactory(final byte[] pepper) {
        this(pepper, HmacAlgorithm.DEFAULT);
    }

    public HkdfDerivationFactory(final byte[] pepper, final IHashAlgorithm algorithm) {
        this.pepper = pepper;
        this.algorithm = algorithm;
        if (algorithm.getHashSize() <= 0) {
            throw new IllegalArgumentException("HashSize should be positive non zero: " + algorithm.getHashSize());
        }
    }

    @Override
    public byte[] getPepper() {
        return pepper;
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    @Override
    public int getExtractLength() {
        return algorithm.getHashSize();
    }

    @Override
    public byte[] extract(final byte[] salt, final byte[] keyMaterial) {
        if (keyMaterial != null && keyMaterial.length > 0) {
            final IHash hash = algorithm.getHashPool().borrowObject();
            try {
                hash.init(HashMode.Sign, new HashKey(algorithm, Bytes.concat(salt, pepper)));
                return hash.doFinal(keyMaterial);
            } finally {
                algorithm.getHashPool().returnObject(hash);
            }
        } else {
            return null;
        }
    }

    @Override
    public byte[] expand(final byte[] key, final byte[] pInfo, final int length) {
        final IHash mac = algorithm.getHashPool().borrowObject();
        try {
            mac.init(HashMode.Sign, new HashKey(algorithm, key));
            final byte[] info;
            if (pInfo == null) {
                info = new byte[0];
            } else {
                info = pInfo;
            }

            byte[] hashRound = new byte[0];
            final java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(length);

            for (int i = 0; i < (int) Math.ceil(length / (double) mac.getHashSize()); i++) {
                mac.update(hashRound);
                mac.update(info);
                mac.update((byte) (i + 1));
                hashRound = mac.doFinal();
                final int size = Math.min(length, hashRound.length);
                final int copySize = Integers.min(buffer.remaining(), size);
                buffer.put(hashRound, 0, copySize);
            }

            return buffer.array();
        } finally {
            algorithm.getHashPool().returnObject(mac);
        }
    }

}