package de.invesdwin.context.security.crypto.verification.hash.algorithm;

import javax.annotation.concurrent.Immutable;

@Immutable
public enum HashAlgorithmType {
    Checksum(true, false, false, false),
    Digest(true, true, false, false),
    Mac(true, true, true, false),
    Signature(true, true, true, true);

    private boolean errorDetection;
    private boolean integrity;
    private boolean authentication;
    private boolean nonRepudiation;

    HashAlgorithmType(final boolean errorDetection, final boolean integrity, final boolean authentication,
            final boolean nonRepudiation) {
        this.errorDetection = errorDetection;
        this.integrity = integrity;
        this.authentication = authentication;
        this.nonRepudiation = nonRepudiation;
    }

    /**
     * Checksums only protect against accidental modification, but are easy to maliciously manipulate. Just add some
     * data and extend the hash.
     */
    public boolean isErrorDetection() {
        return errorDetection;
    }

    /**
     * Another core concept in cryptography is message integrity. While encryption keeps messages confidential, data
     * integrity ensures full confidence that the data you are receiving is the actual valid data from the sender, and
     * has not been tampered with or manipulated.
     * 
     * A checksum does not provide integrity, it only verifies for accidental errors.
     * 
     * https://medium.com/@emilywilliams_43022/cryptography-101-data-integrity-and-authenticated-encryption-af273f30018e
     * 
     * https://security.stackexchange.com/questions/194600/checksum-vs-hash-differences-and-similarities
     */
    public boolean isIntegrity() {
        return integrity;
    }

    /**
     * Returns true if this is not just a verification based on a message digest but an authentication based on a mac as
     * well.
     * 
     * Normally only authenticated hashes require a key on initialization. For non-authenticated hashes the key will
     * then be used as a pepper (a static salt).
     */
    public boolean isAuthentication() {
        return authentication;
    }

    /**
     * signatures ensure that the sender is actually the one that created the message.
     * 
     * https://crypto.stackexchange.com/questions/5646/what-are-the-differences-between-a-digital-signature-a-mac-and-a-hash
     */
    public boolean isNonRepudiation() {
        return nonRepudiation;
    }
}
