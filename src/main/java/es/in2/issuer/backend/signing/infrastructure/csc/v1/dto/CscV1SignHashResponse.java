package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record CscV1SignHashResponse(
        @JsonProperty("signatures") List<String> signatures
) {}
