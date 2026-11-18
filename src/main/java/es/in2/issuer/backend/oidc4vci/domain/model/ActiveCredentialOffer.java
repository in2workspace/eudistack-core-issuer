package es.in2.issuer.backend.oidc4vci.domain.model;

/**
 * The credential offer currently valid for an issuance, with the grant it carries. Exactly one of
 * {@code preAuthorizedCode} and {@code issuerState} is set, depending on the grant type.
 *
 * @param nonce             key of the offer in the credential offer store
 * @param preAuthorizedCode pre-authorized code of the offer, or {@code null}
 * @param issuerState       issuer_state of the offer, or {@code null}
 */
public record ActiveCredentialOffer(String nonce, String preAuthorizedCode, String issuerState) {
}
