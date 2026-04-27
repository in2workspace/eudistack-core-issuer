package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
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
        Map<String, CredentialIssuerMetadata.CredentialConfiguration> filteredConfigs =
                enabledIds.isEmpty() ? allConfigurations :
                        allConfigurations.entrySet().stream()
                                .filter(e -> enabledIds.contains(e.getKey()))
                                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return CredentialIssuerMetadata.builder()
                .credentialIssuer(baseUrl)
                .credentialEndpoint(baseUrl + OID4VCI_CREDENTIAL_PATH)
                .nonceEndpoint(baseUrl + OID4VCI_NONCE_PATH)
                .notificationEndpoint(baseUrl + OID4VCI_NOTIFICATION_PATH)
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

        String vct = profile.sdJwt() != null ? profile.sdJwt().vct() : null;

        CredentialIssuerMetadata.CredentialConfiguration.CredentialDefinition credDef = null;
        if (profile.credentialDefinition() != null
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
