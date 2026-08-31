package es.in2.issuer.backend.oidc4vci.domain.model;

/**
 * The attestation-based client authentication headers of OAuth Attestation-Based Client
 * Authentication: {@code OAuth-Client-Attestation} and {@code OAuth-Client-Attestation-PoP}.
 *
 * <p>Carried as a pair so endpoints that authenticate the client do not grow two more
 * positional parameters each.
 */
public record ClientAttestationHeaders(String attestation, String pop) {
}
