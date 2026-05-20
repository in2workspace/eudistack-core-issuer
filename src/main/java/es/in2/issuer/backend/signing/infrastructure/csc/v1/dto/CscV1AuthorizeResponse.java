package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CscV1AuthorizeResponse(
        @JsonProperty("SAD") String sad
) {}
