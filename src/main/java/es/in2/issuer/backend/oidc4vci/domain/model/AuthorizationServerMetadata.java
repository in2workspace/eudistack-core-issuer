package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;
import java.util.Set;

@Builder
public record AuthorizationServerMetadata(
        @JsonProperty(value = "issuer", required = true) String issuer,
        @JsonProperty(value = "token_endpoint", required = true) String tokenEndpoint,
        @JsonProperty(value = "response_types_supported", required = true) Set<String> responseTypesSupported,
        @JsonProperty(value = "pre-authorized_grant_anonymous_access_supported", required = true) boolean preAuthorizedGrantAnonymousAccessSupported,
        @JsonProperty(value = "authorization_endpoint") String authorizationEndpoint,
        @JsonProperty(value = "pushed_authorization_request_endpoint") String pushedAuthorizationRequestEndpoint,
        @JsonProperty(value = "nonce_endpoint") String nonceEndpoint,
        @JsonProperty(value = "grant_types_supported") Set<String> grantTypesSupported,
        @JsonProperty(value = "code_challenge_methods_supported") List<String> codeChallengeMethodsSupported,
        @JsonProperty(value = "dpop_signing_alg_values_supported") List<String> dpopSigningAlgValuesSupported,
        @JsonProperty(value = "token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty(value = "require_pushed_authorization_requests") Boolean requirePushedAuthorizationRequests,
        @JsonProperty(value = "authorization_response_iss_parameter_supported") Boolean authorizationResponseIssParameterSupported,
        @JsonProperty(value = "jwks_uri") String jwksUri
) {
}
