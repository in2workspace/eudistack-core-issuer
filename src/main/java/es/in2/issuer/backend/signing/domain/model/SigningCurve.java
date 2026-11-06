package es.in2.issuer.backend.signing.domain.model;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Optional;

/**
 * The elliptic curves a signing certificate of the own-key modality may hold. Only P-256 for now: the EUD-251
 * PRD asks for a P-256 key and ES256 is ECDSA on P-256 (RFC 7518 §3.4).
 *
 * <p>A curve is recognised by its exact domain parameters, never by its size: secp256k1 or brainpoolP256r1
 * are 256-bit curves too, and neither is P-256.
 */
public enum SigningCurve {

    P_256("secp256r1");

    private final ECParameterSpec parameters;

    SigningCurve(String jdkName) {
        this.parameters = parametersOf(jdkName);
    }

    /** The curve of the public key of the certificate; empty for an RSA key or for a curve not listed here. */
    public static Optional<SigningCurve> of(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate is required");
        }
        if (!(certificate.getPublicKey() instanceof ECPublicKey publicKey)) {
            return Optional.empty();
        }
        return Arrays.stream(values()).filter(curve -> curve.matches(publicKey.getParams())).findFirst();
    }

    /** ECParameterSpec has no equals(), so the curve, generator, order and cofactor are compared one by one. */
    private boolean matches(ECParameterSpec params) {
        return parameters.getCurve().equals(params.getCurve())
                && parameters.getGenerator().equals(params.getGenerator())
                && parameters.getOrder().equals(params.getOrder())
                && parameters.getCofactor() == params.getCofactor();
    }

    private static ECParameterSpec parametersOf(String jdkName) {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(jdkName));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("The JDK does not provide " + jdkName, e);
        }
    }
}
