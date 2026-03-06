package es.in2.issuer.backend.oidc4vci.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import lombok.Builder;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CredentialIssuerMetadata(
        @JsonProperty(value = "credential_issuer", required = true) String credentialIssuer,
        @JsonProperty(value = "credential_endpoint", required = true) String credentialEndpoint,
        @JsonProperty("nonce_endpoint") String nonceEndpoint,
        @JsonProperty("notification_endpoint") String notificationEndpoint,
        @JsonProperty(value = "credential_configurations_supported", required = true)
        Map<String, CredentialConfiguration> credentialConfigurationsSupported,
        @JsonProperty("display") List<CredentialProfile.DisplayInfo> display
) {

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialConfiguration(
            @JsonProperty("format") String format,
            @JsonProperty("scope") String scope,
            @JsonProperty("cryptographic_binding_methods_supported") Set<String> cryptographicBindingMethodsSupported,
            @JsonProperty("credential_signing_alg_values_supported") Set<String> credentialSigningAlgValuesSupported,
            @JsonProperty("proof_types_supported") Map<String, CredentialProfile.ProofTypeConfig> proofTypesSupported,
            @JsonProperty("credential_metadata") CredentialProfile.CredentialMetadata credentialMetadata,
            @JsonProperty("vct") String vct,
            @JsonProperty("credential_definition") CredentialDefinition credentialDefinition
    ) {
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public record CredentialDefinition(
                @JsonProperty("type") List<String> type
        ) {}
    }
}
