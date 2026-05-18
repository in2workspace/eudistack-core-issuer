package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record CscV1SignHashRequest(
        @JsonProperty("credentialID") String credentialId,
        @JsonProperty("SAD")          String sad,
        @JsonProperty("hash")         List<String> hash,
        @JsonProperty("hashAlgo")     String hashAlgo,
        @JsonProperty("signAlgo")     String signAlgo
) {}
