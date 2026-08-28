package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.domain.util.Constants;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;

@Slf4j
@Service
public class CredentialIssuerMetadataServiceImpl implements CredentialIssuerMetadataService {

    private static final Set<String> W3C_VC_FORMATS = Set.of(Constants.JWT_VC_JSON, "jwt_vc_json-ld", "ldp_vc");

    private final Map<String, CredentialIssuerMetadata.CredentialConfiguration> allConfigurations;
    private final TenantCredentialProfileService tenantCredentialProfileService;

    public CredentialIssuerMetadataServiceImpl(CredentialProfileRegistry credentialProfileRegistry,
                                                TenantCredentialProfileService tenantCredentialProfileService) {
        this.tenantCredentialProfileService = tenantCredentialProfileService;

        this.allConfigurations = credentialProfileRegistry.getAllProfiles().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> mapProfileToConfiguration(entry.getValue())
                ));

        log.info("CredentialIssuerMetadata initialized: configurations={}", allConfigurations.keySet());
    }

    @Override
    public Mono<CredentialIssuerMetadata> getCredentialIssuerMetadata(String publicIssuerBaseUrl) {
        return tenantCredentialProfileService.getEnabledConfigurationIds()
                .map(enabledIds -> buildMetadata(publicIssuerBaseUrl, enabledIds));
    }

    private CredentialIssuerMetadata buildMetadata(String baseUrl, Set<String> enabledIds) {
        // No enabled ids ⇒ no supported configurations: the tenant catalog must be
        // configured explicitly before the issuer advertises anything.
        Map<String, CredentialIssuerMetadata.CredentialConfiguration> filteredConfigs =
                allConfigurations.entrySet().stream()
                        .filter(e -> enabledIds.contains(e.getKey()))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return CredentialIssuerMetadata.builder()
                .credentialIssuer(baseUrl)
                .credentialEndpoint(baseUrl + OID4VCI_CREDENTIAL_PATH)
                .nonceEndpoint(baseUrl + OID4VCI_NONCE_PATH)
                .notificationEndpoint(baseUrl + OID4VCI_NOTIFICATION_PATH)
                .deferredCredentialEndpoint(baseUrl + OID4VCI_DEFERRED_CREDENTIAL_PATH)
                .credentialConfigurationsSupported(filteredConfigs)
                .build();
    }

    private static CredentialIssuerMetadata.CredentialConfiguration mapProfileToConfiguration(CredentialProfile profile) {
        Set<String> bindingMethods = profile.cryptographicBindingMethodsSupported();
        if (bindingMethods != null && bindingMethods.isEmpty()) {
            bindingMethods = null;
        }

        Map<String, CredentialProfile.ProofTypeConfig> proofTypes = profile.proofTypesSupported();
        if (proofTypes != null && proofTypes.isEmpty()) {
            proofTypes = null;
        }

        // OID4VCI 1.0 Final section 12.2.4 defines credential-configuration parameters per
        // format: `vct` only for dc+sd-jwt, `credential_definition` only for the W3C VC
        // formats. Publishing either outside its format is reported as an unexpected
        // metadata field by the OIDF conformance suite.
        String vct = Constants.DC_SD_JWT.equals(profile.format()) && profile.sdJwt() != null
                ? profile.sdJwt().vct()
                : null;

        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition credDef = null;
        if (W3C_VC_FORMATS.contains(profile.format())
                && profile.credentialDefinition() != null
                && profile.credentialDefinition().type() != null
                && !profile.credentialDefinition().type().isEmpty()) {
            credDef = CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition.builder()
                    .type(profile.credentialDefinition().type())
                    .build();
        }

        return CredentialIssuerMetadata.CredentialConfiguration.builder()
                .format(profile.format())
                .scope(profile.scope())
                .cryptographicBindingMethodsSupported(bindingMethods)
                .credentialSigningAlgValuesSupported(profile.credentialSigningAlgValuesSupported())
                .proofTypesSupported(proofTypes)
                .credentialMetadata(profile.credentialMetadata())
                .vct(vct)
                .credentialDefinition(credDef)
                .build();
    }
}
