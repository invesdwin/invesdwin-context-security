package de.invesdwin.context.security.crypto.key.certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.annotation.concurrent.Immutable;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import de.invesdwin.util.time.date.FDate;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.range.TimeRange;

/**
 * Orignal from: https://github.com/misterpki/selfsignedcert
 */
@Immutable
public final class SelfSignedCertGenerator {

    /**
     * 398 days (recommended 397 days) are currently the limit for browsers:
     * https://www.ssl.com/blogs/398-day-browser-limit-for-ssl-tls-certificates-begins-september-1-2020/
     * 
     * Though we don't have to follow this recommendation because we are self signing anyway and don't want to be
     * trusted by browsers anyhow. But 397 days is enough to roll over to a new certificate by restarting the servers
     * once a year.
     */
    public static final int MAX_BROWSER_VALIDITY_DAYS = 397;

    private SelfSignedCertGenerator() {
    }

    /**
     * If someone wants to use the certificate outside of its range, he can just manipulate his system clock or ignore
     * the validity anyhow.
     * 
     * You can just use an unlimited validity for private communication where you don't want to bother with certificate
     * renewals besides changes in the pepper.
     */
    public static TimeRange newMilleniumValidity() {
        //
        final FDate milleniumStart = new FDate().truncate(FTimeUnit.MILLENIA);
        final FDate notBefore = milleniumStart.addYears(-1);
        final FDate notAfter = milleniumStart.add(FTimeUnit.MILLENIA, 1).addYears(1);
        return new TimeRange(notBefore, notAfter);
    }

    public static TimeRange newBrowserValidity() {
        final FDate now = new FDate();
        return new TimeRange(now, now.addDays(MAX_BROWSER_VALIDITY_DAYS));
    }

    /**
     * Generates a self signed certificate using the BouncyCastle lib.
     *
     * @param keyPair
     *            used for signing the certificate with PrivateKey
     * @param hashAlgorithm
     *            Hash function
     * @param cn
     *            Common Name to be used in the subject dn
     * @param days
     *            validity period in days of the certificate
     *
     * @return self-signed X509Certificate
     *
     * @throws OperatorCreationException
     *             on creating a key id
     * @throws CertIOException
     *             on building JcaContentSignerBuilder
     * @throws CertificateException
     *             on getting certificate from provider
     */
    public static X509Certificate generate(final KeyPair keyPair, final String hashAlgorithm, final String cn,
            final TimeRange validity) throws OperatorCreationException, CertificateException, CertIOException {
        final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(keyPair.getPrivate());
        final X500Name x500Name = new X500Name("CN=" + cn);
        final X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(x500Name,
                BigInteger.valueOf(validity.getFrom().millisValue()), validity.getFrom().dateValue(),
                validity.getTo().dateValue(), x500Name, keyPair.getPublic())
                        .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
                        .addExtension(Extension.authorityKeyIdentifier, false,
                                createAuthorityKeyId(keyPair.getPublic()))
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider())
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    /**
     * Creates the hash value of the public key.
     *
     * @param publicKey
     *            of the certificate
     *
     * @return SubjectKeyIdentifier hash
     *
     * @throws OperatorCreationException
     */
    private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    /**
     * Creates the hash value of the authority public key.
     *
     * @param publicKey
     *            of the authority certificate
     *
     * @return AuthorityKeyIdentifier hash
     *
     * @throws OperatorCreationException
     */
    private static AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
            throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

}
