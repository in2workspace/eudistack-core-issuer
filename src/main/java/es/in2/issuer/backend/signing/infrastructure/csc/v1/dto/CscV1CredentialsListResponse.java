package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record CscV1CredentialsListResponse(
        @JsonProperty("credentialIDs") List<String> credentialIds
) {}
