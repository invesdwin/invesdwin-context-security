package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding;

import java.security.spec.MGF1ParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import de.invesdwin.context.security.crypto.verification.hash.algorithm.DigestAlgorithm;

@Immutable
public enum OaepPadding {
    @Deprecated
    OAEPWithMD5AndMGF1Padding("OAEPWithMD5AndMGF1Padding", DigestAlgorithm.MD5),
    @SuppressWarnings("deprecation")
    OAEPWithSHA1AndMGF1Padding("OAEPWithSHA1AndMGF1Padding", DigestAlgorithm.SHA_1),
    OAEPWithSHA224AndMGF1Padding("OAEPWithSHA224AndMGF1Padding", DigestAlgorithm.SHA_224),
    OAEPWithSHA256AndMGF1Padding("OAEPWithSHA256AndMGF1Padding", DigestAlgorithm.SHA_256),
    OAEPWithSHA384AndMGF1Padding("OAEPWithSHA384AndMGF1Padding", DigestAlgorithm.SHA_384),
    OAEPWithSHA512AndMGF1Padding("OAEPWithSHA512AndMGF1Padding", DigestAlgorithm.SHA_512),
    OAEPWithSHA3_224AndMGF1Padding("OAEPWithSHA3-224AndMGF1Padding", DigestAlgorithm.SHA3_224),
    OAEPWithSHA3_256AndMGF1Padding("OAEPWithSHA3-256AndMGF1Padding", DigestAlgorithm.SHA3_256),
    OAEPWithSHA3_384AndMGF1Padding("OAEPWithSHA3-384AndMGF1Padding", DigestAlgorithm.SHA3_384),
    OAEPWithSHA3_512AndMGF1Padding("OAEPWithSHA3-512AndMGF1Padding", DigestAlgorithm.SHA3_512);

    /**
     * SHA256 is recommended just because SHA1 has a bad reputation despite no attach being known when used with RSA.
     * Both are accelerated in intel instructions.
     * 
     * https://stackoverflow.com/questions/60095609/rsa-and-oaep-choosing-or-not-choosing-the-hash-algorithm
     * 
     * https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html
     */
    public static final OaepPadding DEFAULT = OAEPWithSHA256AndMGF1Padding;

    private String algorithm;
    private DigestAlgorithm digestAlgorithm;

    private OAEPParameterSpec javaParam;
    private OAEPParameterSpec commonParam;

    OaepPadding(final String algorithm, final DigestAlgorithm digestAlgorithm) {
        this.algorithm = algorithm;
        this.digestAlgorithm = digestAlgorithm;
        this.javaParam = new OAEPParameterSpec(digestAlgorithm.getAlgorithm(), "MGF1", MGF1ParameterSpec.SHA1,
                PSource.PSpecified.DEFAULT);
        this.commonParam = new OAEPParameterSpec(digestAlgorithm.getAlgorithm(), "MGF1",
                new MGF1ParameterSpec(digestAlgorithm.getAlgorithm()), PSource.PSpecified.DEFAULT);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    @Override
    public String toString() {
        return algorithm;
    }

    /**
     * Always uses SHA-1 for MGF1.
     */
    public OAEPParameterSpec getJavaParam() {
        return javaParam;
    }

    /**
     * OAEPParameterSpec can specify the SHA version and provide compatibility with javascript and c#:
     * 
     * https://stackoverflow.com/questions/55525628/rsa-encryption-with-oaep-between-java-and-javascript
     * 
     * https://stackoverflow.com/questions/64871945/encrypt-text-with-rsa-ecb-oaepwithmd5andmgf1padding-in-c-sharp
     */
    public OAEPParameterSpec getCommonParam() {
        return commonParam;
    }

}
