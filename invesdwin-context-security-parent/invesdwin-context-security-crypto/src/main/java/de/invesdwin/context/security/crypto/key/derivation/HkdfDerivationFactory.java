package de.invesdwin.context.security.crypto.key.derivation;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.CryptoProperties;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.HmacAlgorithm;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.util.math.Bytes;

/**
 * Adapted from: https://github.com/NetRiceCake/HKDF/blob/master/src/main/java/com/github/netricecake/hkdf/HKDF.java
 */
@Immutable
public class HkdfDerivationFactory implements IDerivationFactory {

    public static final HkdfDerivationFactory INSTANCE = new HkdfDerivationFactory();

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
                hash.init(algorithm.wrapKey(Bytes.concat(salt, pepper)));
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
            mac.init(algorithm.wrapKey(key));
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
                buffer.put(hashRound, 0, size);
            }

            return buffer.array();
        } finally {
            algorithm.getHashPool().returnObject(mac);
        }
    }

}