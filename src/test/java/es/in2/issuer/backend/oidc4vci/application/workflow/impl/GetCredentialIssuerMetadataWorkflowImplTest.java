package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.model.CredentialIssuerMetadata;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuerMetadataService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GetCredentialIssuerMetadataWorkflowImplTest {

    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;

    @InjectMocks
    private GetCredentialIssuerMetadataWorkflowImpl getCredentialIssuerMetadataWorkflow;

    @Test
    void testExecute() {
        // Arrange
        String processId = "b731b463-7473-4f97-be7a-658ec0b5dbc9";
        CredentialIssuerMetadata expectedCredentialIssuerMetadata = CredentialIssuerMetadata.builder()
                .credentialIssuer("https://issuer.example.com")
                .credentialEndpoint("https://issuer.example.com/oid4vci/v1/credential")
                .credentialConfigurationsSupported(Map.of(
                        "learcredential.employee.w3c.4", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("lear_credential_employee")
                                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .proofTypesSupported(Map.of("jwt", CredentialProfile.ProofTypeConfig.builder()
                                        .proofSigningAlgValuesSupported(Set.of("ES256"))
                                        .build()))
                                .credentialMetadata(null)
                                .vct(null)
                                .build(),
                        "learcredential.machine.w3c.3", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("lear_credential_machine")
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialMetadata(null)
                                .vct(null)
                                .build(),
                        "VerifiableCertification", CredentialIssuerMetadata.CredentialConfiguration.builder()
                                .format("jwt_vc_json")
                                .scope("verifiable_certification")
                                .credentialSigningAlgValuesSupported(Set.of("ES256"))
                                .credentialMetadata(null)
                                .vct(null)
                                .build()
                ))
                .build();
        // Mock
        when(getCredentialIssuerMetadataWorkflow.execute(processId))
                .thenReturn(Mono.just(expectedCredentialIssuerMetadata));
        // Act
        Mono<CredentialIssuerMetadata> result = getCredentialIssuerMetadataWorkflow.execute(processId);
        // Assert
        assertEquals(expectedCredentialIssuerMetadata, result.block());
    }

}