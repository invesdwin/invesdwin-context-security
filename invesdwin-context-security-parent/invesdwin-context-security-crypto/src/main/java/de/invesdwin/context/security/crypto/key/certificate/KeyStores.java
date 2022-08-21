package de.invesdwin.context.security.crypto.key.certificate;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.annotation.concurrent.Immutable;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

import de.invesdwin.util.math.Characters;

/**
 * Extracted from: io.netty.handler.ssl.SslContext
 */
@Immutable
public final class KeyStores {

    public static final String KEY_ENTRY_ALIAS = "key";

    private KeyStores() {}

    public static TrustManagerFactory buildTrustManagerFactory(final X509Certificate... certCollection)
            throws Exception {
        return buildTrustManagerFactory(certCollection, null, null);
    }

    public static TrustManagerFactory buildTrustManagerFactory(final X509Certificate[] certCollection,
            final TrustManagerFactory pTrustManagerFactory, final String pKeyStoreType) throws Exception {
        String keyStoreType = pKeyStoreType;
        if (keyStoreType == null) {
            keyStoreType = KeyStore.getDefaultType();
        }
        final KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(null, null);

        int i = 1;
        for (final X509Certificate cert : certCollection) {
            final String alias = Integer.toString(i);
            ks.setCertificateEntry(alias, cert);
            i++;
        }

        TrustManagerFactory trustManagerFactory = pTrustManagerFactory;
        // Set up trust manager factory to use our key store.
        if (trustManagerFactory == null) {
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        }
        trustManagerFactory.init(ks);

        return trustManagerFactory;
    }

    public static KeyStore buildKeyStore(final PrivateKey key, final X509Certificate... certChain) throws Exception {
        return buildKeyStore(key, certChain, null, null);
    }

    public static KeyStore buildKeyStore(final PrivateKey key, final X509Certificate[] certChain,
            final char[] keyPasswordChars, final String pKeyStoreType) throws Exception {
        String keyStoreType = pKeyStoreType;
        if (keyStoreType == null) {
            keyStoreType = KeyStore.getDefaultType();
        }
        final KeyStore ks = KeyStore.getInstance(keyStoreType);
        ks.load(null, null);
        ks.setKeyEntry(KEY_ENTRY_ALIAS, key, keyPasswordChars, certChain);
        return ks;
    }

    public static KeyManagerFactory buildKeyManagerFactory(final PrivateKey key, final X509Certificate... certChainFile)
            throws Exception {
        return buildKeyManagerFactory(key, certChainFile, null, null, null, null);
    }

    public static KeyManagerFactory buildKeyManagerFactory(final PrivateKey key, final X509Certificate[] certChainFile,
            final String pKeyAlgorithm, final String keyPassword, final KeyManagerFactory kmf,
            final String keyStoreType) throws Exception {
        String keyAlgorithm = pKeyAlgorithm;
        if (keyAlgorithm == null) {
            keyAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        }
        final char[] keyPasswordChars = keyStorePassword(keyPassword);
        final KeyStore ks = buildKeyStore(key, certChainFile, keyPasswordChars, keyStoreType);
        return buildKeyManagerFactory(ks, keyAlgorithm, keyPasswordChars, kmf);
    }

    public static KeyManagerFactory buildKeyManagerFactory(final KeyStore ks, final String pKeyAlgorithm,
            final char[] keyPasswordChars, final KeyManagerFactory pKmf) throws Exception {
        // Set up key manager factory to use our key store
        KeyManagerFactory kmf = pKmf;
        if (kmf == null) {
            String keyAlgorithm = pKeyAlgorithm;
            if (keyAlgorithm == null) {
                keyAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
            }
            kmf = KeyManagerFactory.getInstance(keyAlgorithm);
        }
        kmf.init(ks, keyPasswordChars);

        return kmf;
    }

    public static char[] keyStorePassword(final String keyPassword) {
        return keyPassword == null ? Characters.EMPTY_ARRAY : keyPassword.toCharArray();
    }

}
