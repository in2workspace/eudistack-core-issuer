package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CscV1CredentialsInfoRequest(
        @JsonProperty("credentialID") String credentialId,
        @JsonProperty("certificates") String certificates,
        @JsonProperty("certInfo")     boolean certInfo,
        @JsonProperty("authInfo")     boolean authInfo
) {}
