package de.invesdwin.context.security.crypto.authentication.mac.algorithm;

import java.security.Key;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.security.crypto.authentication.mac.IMac;
import de.invesdwin.context.security.crypto.authentication.mac.pool.MacObjectPool;
import de.invesdwin.context.security.crypto.authentication.mac.wrapper.CipherMac;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.AesKeyLength;
import de.invesdwin.context.security.crypto.encryption.cipher.algorithm.ICipherAlgorithm;
import de.invesdwin.context.security.crypto.encryption.cipher.iv.CipherCountedIV;
import de.invesdwin.util.concurrent.pool.IObjectPool;

@Immutable
public enum CmacAlgorithm implements IMacAlgorithm {
    CMAC_AES_128(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._128.getBytes()),
    CMAC_AES_196(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._196.getBytes()),
    CMAC_AES_256(AesAlgorithm.AES_CBC_PKCS5Padding, AesKeyLength._256.getBytes());

    public static final CmacAlgorithm DEFAULT = CMAC_AES_256;
    private final ICipherAlgorithm algorithm;
    private final MacObjectPool macPool;
    private int macLength;

    CmacAlgorithm(final ICipherAlgorithm algorithm, final int macLength) {
        this.algorithm = algorithm;
        this.macPool = new MacObjectPool(this);
        this.macLength = macLength;
    }

    @Override
    public String getAlgorithm() {
        return algorithm.getAlgorithm();
    }

    @Override
    public int getMacLength() {
        return macLength;
    }

    @Override
    public IMac newMac() {
        return new CipherMac(algorithm, new CipherCountedIV(algorithm));
    }

    @Override
    public Key wrapKey(final byte[] key) {
        return algorithm.wrapKey(key);
    }

    @Override
    public IObjectPool<IMac> getMacPool() {
        return macPool;
    }

}
