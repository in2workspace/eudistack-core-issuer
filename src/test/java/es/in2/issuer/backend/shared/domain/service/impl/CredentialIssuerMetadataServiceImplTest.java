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

import java.util.Map;
import java.util.Set;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerMetadataServiceImplTest {

    private static final String ISSUER_URL = "https://issuer.example.com";

    @Mock
    private IssuerProperties appConfig;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @Test
    void shouldGetCredentialIssuerMetadataSuccessfully() {
        // Arrange
        when(appConfig.getIssuerBackendUrl()).thenReturn(ISSUER_URL);

        CredentialProfile learProfile = CredentialProfile.builder()
                .credentialConfigurationId(LEAR_CREDENTIAL_EMPLOYEE)
                .format(Constants.JWT_VC_JSON)
                .scope("lear_credential_employee")
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                        .build()))
                .build();

        when(credentialProfileRegistry.getAllProfiles()).thenReturn(Map.of(LEAR_CREDENTIAL_EMPLOYEE, learProfile));

        // Construct service (metadata is built in the constructor)
        var service = new CredentialIssuerMetadataServiceImpl(appConfig, credentialProfileRegistry);

        // Act
        CredentialIssuerMetadata metadata = service.getCredentialIssuerMetadata();

        // Assert
        assertThat(metadata.credentialIssuer()).isEqualTo(ISSUER_URL);
        assertThat(metadata.credentialEndpoint()).isEqualTo(ISSUER_URL + OID4VCI_CREDENTIAL_PATH);
        assertThat(metadata.nonceEndpoint()).isEqualTo(ISSUER_URL + OID4VCI_NONCE_PATH);

        Map<String, CredentialIssuerMetadata.CredentialConfiguration> configs = metadata.credentialConfigurationsSupported();
        assertThat(configs).containsKeys(LEAR_CREDENTIAL_EMPLOYEE);

        CredentialIssuerMetadata.CredentialConfiguration learCredentialEmployeeConfig = configs.get(LEAR_CREDENTIAL_EMPLOYEE);
        assertThat(learCredentialEmployeeConfig.format()).isEqualTo(Constants.JWT_VC_JSON);
        assertThat(learCredentialEmployeeConfig.scope()).isEqualTo("lear_credential_employee");
        assertThat(learCredentialEmployeeConfig.cryptographicBindingMethodsSupported()).containsExactly("did:key");
        assertThat(learCredentialEmployeeConfig.credentialSigningAlgValuesSupported()).containsExactly("ES256");

        Map<String, CredentialProfile.ProofTypeConfig> proofTypes = learCredentialEmployeeConfig.proofTypesSupported();
        assertThat(proofTypes).containsKey("jwt");
        assertThat(proofTypes.get("jwt").proofSigningAlgValuesSupported()).containsExactly("ES256");
    }
}
