package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

public record CscV1SignDocRequest(
        @JsonProperty("credentialID")        String credentialId,
        @JsonProperty("SAD")                 String sad,
        @JsonProperty("signatureQualifier")  String signatureQualifier,
        @JsonProperty("documents")           List<Map<String, String>> documents
) {}
