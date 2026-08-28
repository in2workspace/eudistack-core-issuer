package es.in2.issuer.backend.signing.infrastructure.csc.v2.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CscV2AuthorizeRequest(
        @JsonProperty("credentialID")  String credentialId,
        @JsonProperty("numSignatures") int numSignatures,
        @JsonProperty("hash")          List<String> hash,
        @JsonProperty("hashAlgo")      String hashAlgo,
        @JsonProperty("authData")      List<Map<String, String>> authData
) {}
