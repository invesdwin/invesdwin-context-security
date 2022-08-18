package de.invesdwin.context.security.crypto.key.derivation;

public interface IDerivationFactory {

    static IDerivationFactory getDefault() {
        return HkdfDerivationFactory.DEFAULT;
    }

    byte[] getPepper();

    String getAlgorithm();

    int getExtractLength();

    byte[] extract(byte[] salt, byte[] keyMaterial);

    byte[] expand(byte[] key, byte[] info, int length);

    /**
     * https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-28
     */
    default byte[] expandLabel(final byte[] key, final String label, final byte[] context, final int length) {
        final byte[] hexLabel = ("tls13 " + label).getBytes();
        final byte[] info = new byte[hexLabel.length + context.length + 4];

        final byte[] hexLength = new byte[2];
        hexLength[0] = (byte) (length >> 8);
        hexLength[1] = (byte) (length);

        System.arraycopy(hexLength, 0, info, 0, 2);
        info[2] = (byte) hexLabel.length;
        System.arraycopy(hexLabel, 0, info, 3, hexLabel.length);
        info[hexLabel.length + 3] = (byte) context.length;
        System.arraycopy(context, 0, info, hexLabel.length + 4, context.length);

        return expand(key, info, length);
    }

}
