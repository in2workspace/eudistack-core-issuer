package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CscV1CredentialsListRequest(
        @JsonProperty("credentialID") String credentialID
) {}
