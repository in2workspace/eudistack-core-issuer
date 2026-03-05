package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.oidc4vci.application.workflow.PreAuthorizedCodeWorkflow;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.domain.util.JwtUtils;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.IssuancePdpService;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialIssuanceWorkflowExecuteWithoutAuthTest {

    @Mock
    private VerifiableCredentialService verifiableCredentialService;
    @Mock
    private StatusListWorkflow statusListWorkflow;
    @Mock
    private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock
    private IssuerProperties appConfig;
    @Mock
    private ProofValidationService proofValidationService;
    @Mock
    private EmailService emailService;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private IssuancePdpService issuancePdpService;
    @Mock
    private CredentialIssuerMetadataService credentialIssuerMetadataService;
    @Mock
    private JwtUtils jwtUtils;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private PreAuthorizedCodeWorkflow preAuthorizedCodeWorkflow;
    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;

    @InjectMocks
    private CredentialIssuanceWorkflowImpl workflow;

    @Test
    void executeWithoutAuthorization_shouldNotCallPdpService() throws JsonProcessingException {
        String processId = "bootstrap-test";
        String json = """
                {
                    "mandatee": {
                        "email": "bootstrap@test.com",
                        "firstName": "Bootstrap",
                        "lastName": "User"
                    },
                    "mandator": {
                        "commonName": "Test Org",
                        "country": "ES",
                        "email": "admin@test.com",
                        "organization": "Test Organization",
                        "organizationIdentifier": "VATES-B12345678",
                        "serialNumber": "12345"
                    },
                    "power": [
                        {
                            "tmf_action": "Execute",
                            "tmf_domain": "DOME",
                            "tmf_function": "Onboarding",
                            "tmf_type": "Domain"
                        }
                    ]
                }
                """;
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.readTree(json);
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .payload(jsonNode)
                .credentialConfigurationId("LEARCredentialEmployee")
                .delivery("immediate")
                .build();

        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), anyString(), eq("bootstrap")))
                .thenReturn(Mono.just(StatusListEntry.builder()
                        .id("entry-id").type("BitstringStatusListEntry")
                        .statusPurpose(StatusPurpose.REVOCATION).statusListIndex("0")
                        .statusListCredential("https://example.com/status").build()));
        when(verifiableCredentialService.generateVc(
                eq(processId), eq(request), eq("bootstrap@test.com"),
                any(CredentialStatus.class), anyString()))
                .thenReturn(Mono.just("tx-code"));
        when(credentialProfileRegistry.getByConfigurationId("LEARCredentialEmployee")).thenReturn(null);

        // The workflow internally calls generateCredentialOffer which needs more mocks.
        // We expect an error from unmocked preAuthorizedCodeWorkflow, but the key assertion
        // is that issuancePdpService.authorize is NEVER called.
        StepVerifier.create(workflow.executeWithoutAuthorization(processId, request))
                .expectError()
                .verify();

        verify(issuancePdpService, never()).authorize(anyString(), anyString(), any(), any());
        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), anyString(), eq("bootstrap"));
    }
}
