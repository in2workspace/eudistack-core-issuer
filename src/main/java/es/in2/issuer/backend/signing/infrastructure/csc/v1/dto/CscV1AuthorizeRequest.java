package es.in2.issuer.backend.signing.infrastructure.csc.v1.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CscV1AuthorizeRequest(
        @JsonProperty("credentialID")  String credentialId,
        @JsonProperty("numSignatures") int numSignatures,
        @JsonProperty("hash")          List<String> hash
) {}
