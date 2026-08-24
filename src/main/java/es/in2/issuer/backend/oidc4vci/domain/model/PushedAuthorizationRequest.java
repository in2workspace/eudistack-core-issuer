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
        @BindParam("authorization_details") String authorizationDetails,
        // RFC 9126 §4: the PAR endpoint generates request_uri - it must never appear as an
        // input parameter of the pushed request itself. Bound here only so ParServiceImpl can
        // detect and reject its presence; it is not used as a normal PAR input beyond that check.
        @BindParam("request_uri") String requestUri
) {
}
