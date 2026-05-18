package es.in2.issuer.backend.signing.infrastructure.csc.v2.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record CscV2SignHashResponse(
        @JsonProperty("signatures") List<String> signatures
) {}
