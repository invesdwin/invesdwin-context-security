package de.invesdwin.context.security.crypto.encryption.cipher.asymmetric.algorithm.padding;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.concurrent.Immutable;
import javax.crypto.spec.OAEPParameterSpec;

@Immutable
public class RsaOaepAlgorithm extends ARsaAlgorithm {

    public static final RsaOaepAlgorithm DEFAULT = new RsaOaepAlgorithm(OaepPadding.DEFAULT.getCommonParam());

    private final OAEPParameterSpec param;

    public RsaOaepAlgorithm(final OAEPParameterSpec param) {
        this.param = param;
    }

    @Override
    public String getAlgorithm() {
        return "RSA/ECB/OAEPPadding";
    }

    @Override
    public AlgorithmParameterSpec getParam() {
        return param;
    }

}
