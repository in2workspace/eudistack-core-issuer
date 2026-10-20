package es.in2.issuer.backend.shared.domain.util.sdjwt;

import java.util.Set;

/**
 * Claim names owned by the issuer or by the SD-JWT VC specification.
 * Business attributes must never use them, otherwise they would clash with
 * the claims the issuer sets on every credential.
 */
public final class SdJwtReservedClaims {

    private static final Set<String> NAMES = Set.of(
            "iss", "sub", "aud", "jti", "iat", "nbf", "exp",
            "vct", "cnf", "status", "_sd", "_sd_alg",
            "validFrom", "validUntil");

    private SdJwtReservedClaims() {}

    public static boolean isReserved(String claimName) {
        return NAMES.contains(claimName);
    }
}
