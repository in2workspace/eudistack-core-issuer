package es.in2.issuer.backend.shared.domain.service.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.util.Constants;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerMetadataServiceImplTest {

    private static final String ISSUER_URL = "https://issuer.example.com";
    private static final String DYNAMIC_URL = "https://issuer.altia.demo.eudistack.net";

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @Test
    void getCredentialIssuerMetadata_withDynamicUrl_returnsMetadataWithDynamicUrl() {
        // Given
        when(appConfig.getIssuerBackendUrl()).thenReturn(ISSUER_URL);

        CredentialProfile learProfile = CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .format(Constants.JWT_VC_JSON)
                .scope("lear_credential_employee")
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                        .build()))
                .build();

        when(credentialProfileRegistry.getAllProfiles()).thenReturn(Map.of("learcredential.employee.w3c.4", learProfile));

        var service = new CredentialIssuerMetadataServiceImpl(appConfig, credentialProfileRegistry);

        // When & Then
        StepVerifier.create(
                        service.getCredentialIssuerMetadata()
                                .contextWrite(ctx -> ctx.put(ISSUER_BASE_URL_CONTEXT_KEY, DYNAMIC_URL))
                )
                .assertNext(metadata -> {
                    assertThat(metadata.credentialIssuer()).isEqualTo(DYNAMIC_URL);
                    assertThat(metadata.credentialEndpoint()).isEqualTo(DYNAMIC_URL + OID4VCI_CREDENTIAL_PATH);
                    assertThat(metadata.nonceEndpoint()).isEqualTo(DYNAMIC_URL + OID4VCI_NONCE_PATH);
                    assertThat(metadata.notificationEndpoint()).isEqualTo(DYNAMIC_URL + OID4VCI_NOTIFICATION_PATH);

                    Map<String, CredentialIssuerMetadata.CredentialConfiguration> configs = metadata.credentialConfigurationsSupported();
                    assertThat(configs).containsKeys("learcredential.employee.w3c.4");
                })
                .verifyComplete();
    }

    @Test
    void getCredentialIssuerMetadata_withoutContextUrl_returnsFallbackUrl() {
        // Given
        when(appConfig.getIssuerBackendUrl()).thenReturn(ISSUER_URL);

        CredentialProfile learProfile = CredentialProfile.builder()
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .format(Constants.JWT_VC_JSON)
                .scope("lear_credential_employee")
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                        .build()))
                .build();

        when(credentialProfileRegistry.getAllProfiles()).thenReturn(Map.of("learcredential.employee.w3c.4", learProfile));

        var service = new CredentialIssuerMetadataServiceImpl(appConfig, credentialProfileRegistry);

        // When & Then
        StepVerifier.create(service.getCredentialIssuerMetadata())
                .assertNext(metadata -> {
                    assertThat(metadata.credentialIssuer()).isEqualTo(ISSUER_URL);
                    assertThat(metadata.credentialEndpoint()).isEqualTo(ISSUER_URL + OID4VCI_CREDENTIAL_PATH);
                    assertThat(metadata.nonceEndpoint()).isEqualTo(ISSUER_URL + OID4VCI_NONCE_PATH);

                    Map<String, CredentialIssuerMetadata.CredentialConfiguration> configs = metadata.credentialConfigurationsSupported();
                    assertThat(configs).containsKeys("learcredential.employee.w3c.4");

                    CredentialIssuerMetadata.CredentialConfiguration learConfig = configs.get("learcredential.employee.w3c.4");
                    assertThat(learConfig.format()).isEqualTo(Constants.JWT_VC_JSON);
                    assertThat(learConfig.scope()).isEqualTo("lear_credential_employee");
                    assertThat(learConfig.cryptographicBindingMethodsSupported()).containsExactly("did:key");
                    assertThat(learConfig.credentialSigningAlgValuesSupported()).containsExactly("ES256");

                    Map<String, CredentialProfile.ProofTypeConfig> proofTypes = learConfig.proofTypesSupported();
                    assertThat(proofTypes).containsKey("jwt");
                    assertThat(proofTypes.get("jwt").proofSigningAlgValuesSupported()).containsExactly("ES256");
                })
                .verifyComplete();
    }
}
