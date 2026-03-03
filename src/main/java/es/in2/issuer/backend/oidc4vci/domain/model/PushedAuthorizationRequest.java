package es.in2.issuer.backend.oidc4vci.domain.model;

import lombok.Builder;
import org.springframework.web.bind.annotation.BindParam;

@Builder
public record PushedAuthorizationRequest(
        @BindParam("response_type") String responseType,
        @BindParam("client_id") String clientId,
        @BindParam("redirect_uri") String redirectUri,
        @BindParam("scope") String scope,
        @BindParam("state") String state,
        @BindParam("code_challenge") String codeChallenge,
        @BindParam("code_challenge_method") String codeChallengeMethod,
        @BindParam("issuer_state") String issuerState,
        @BindParam("authorization_details") String authorizationDetails
) {
}
