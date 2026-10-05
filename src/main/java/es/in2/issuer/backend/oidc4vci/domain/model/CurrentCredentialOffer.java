package es.in2.issuer.backend.oidc4vci.domain.model;

public record CurrentCredentialOffer(String nonce, String grantType, String grantKey) {
}
