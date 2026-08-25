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
        @JsonProperty("deferred_credential_endpoint") String deferredCredentialEndpoint,
        @JsonProperty(value = "credential_configurations_supported", required = true)
        Map<String, CredentialConfiguration> credentialConfigurationsSupported,
        @JsonProperty("display") List<CredentialProfile.DisplayInfo> display
) {

    /**
     * One entry of {@code credential_configurations_supported}.
     *
     * <p>Everything here is an OID4VCI 1.0 registered member except {@code cnf_required}, which is a
     * deliberate extension: holder binding is decided by the conjunction {@code cnf_required && no
     * cryptographic_binding_methods_supported} (see {@code CredentialProfile#holderKeyRequired()}),
     * and publishing only the second half left every client unable to tell a bearer credential from
     * one whose holder key it has to supply itself. Wallets ignore unknown members, and for a wallet
     * the flag is in any case redundant with {@code proof_types_supported}.
     */
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CredentialConfiguration(
            @JsonProperty("format") String format,
            @JsonProperty("scope") String scope,
            @JsonProperty("cryptographic_binding_methods_supported") Set<String> cryptographicBindingMethodsSupported,
            /**
             * Whether the credential carries a {@code cnf} claim at all. Serialized even when
             * {@code false}: an explicit {@code false} is what lets a client distinguish "this issuer
             * says the credential is bearer" from "this issuer does not publish the flag".
             */
            @JsonProperty("cnf_required") boolean cnfRequired,
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
