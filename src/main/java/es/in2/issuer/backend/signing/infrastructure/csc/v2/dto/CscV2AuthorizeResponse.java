package es.in2.issuer.backend.signing.infrastructure.csc.v2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record CscV2AuthorizeResponse(
        @JsonProperty("SAD") String sad
) {}
