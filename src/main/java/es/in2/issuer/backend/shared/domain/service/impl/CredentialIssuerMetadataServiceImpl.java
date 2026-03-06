package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;
import static es.in2.issuer.backend.shared.domain.util.HttpUtils.ensureUrlHasProtocol;

@Slf4j
@Service
public class CredentialIssuerMetadataServiceImpl implements CredentialIssuerMetadataService {

    private final CredentialIssuerMetadata cachedMetadata;

    public CredentialIssuerMetadataServiceImpl(IssuerProperties appConfig,
                                                CredentialProfileRegistry credentialProfileRegistry) {
        String credentialIssuerUrl = ensureUrlHasProtocol(appConfig.getIssuerBackendUrl());

        Map<String, CredentialIssuerMetadata.CredentialConfiguration> configs =
                credentialProfileRegistry.getAllProfiles().entrySet().stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                entry -> mapProfileToConfiguration(entry.getValue())
                        ));

        this.cachedMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer(credentialIssuerUrl)
                .credentialEndpoint(credentialIssuerUrl + OID4VCI_CREDENTIAL_PATH)
                .nonceEndpoint(credentialIssuerUrl + OID4VCI_NONCE_PATH)
                .notificationEndpoint(credentialIssuerUrl + OID4VCI_NOTIFICATION_PATH)
                .credentialConfigurationsSupported(configs)
                .build();

        log.info("CredentialIssuerMetadata cached at startup: issuer={}, configurations={}",
                credentialIssuerUrl, configs.keySet());
    }

    @Override
    public CredentialIssuerMetadata getCredentialIssuerMetadata() {
        return cachedMetadata;
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
