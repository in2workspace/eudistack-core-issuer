package es.in2.issuer.backend.oidc4vci.domain.model;

import lombok.Builder;

@Builder
public record AuthorizationCodeData(
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String issuerState,
        String scope,
        String dpopJkt
) {
}
