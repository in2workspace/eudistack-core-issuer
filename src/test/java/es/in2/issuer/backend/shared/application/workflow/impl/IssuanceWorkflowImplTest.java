package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.CredentialDataSetBuilderService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.GrantsService;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.infrastructure.config.security.service.IssuancePdpService;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceWorkflowImplTest {

    @Mock
    private CredentialDataSetBuilderService credentialDataSetBuilderService;
    @Mock
    private IssuanceService issuanceService;
    @Mock
    private GrantsService grantsService;
    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private IssuerProperties appConfig;
    @Mock
    private IssuancePdpService issuancePdpService;
    @Mock
    private PayloadSchemaValidator payloadSchemaValidator;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private IssuanceMetrics issuanceMetrics;
    @Mock
    private AuditService auditService;

    @InjectMocks
    private IssuanceWorkflowImpl workflow;

    @Test
    void executeShouldCompleteFullIssuanceFlow() {
        String processId = "test-process";
        String configId = "LEARCredentialEmployee";
        String idToken = "id-token";
        JsonNode payload = new ObjectMapper().createObjectNode().put("name", "Test");
        UUID issuanceId = UUID.randomUUID();

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId(configId)
                .payload(payload)
                .delivery("email")
                .email("test@example.com")
                .build();

        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();

        IssuanceCreationRequest creationRequest = IssuanceCreationRequest.builder()
                .issuanceId(issuanceId.toString())
                .credentialType(configId)
                .email("test@example.com")
                .delivery("email")
                .build();

        Issuance savedProcedure = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialOfferRefreshToken("refresh-token-123")
                .build();

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode("pre-auth-code")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .build())
                .authorizationCode(AuthorizationCodeGrant.builder().issuerState("state").build())
                .build();
        GrantsResult grantsResult = new GrantsResult(grants, "1234");

        when(credentialProfileRegistry.getByConfigurationId(configId)).thenReturn(profile);
        when(payloadSchemaValidator.validate(anyString(), any())).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(credentialDataSetBuilderService.buildDataSet(anyString(), eq(request))).thenReturn(Mono.just(creationRequest));
        when(issuanceService.createIssuance(creationRequest)).thenReturn(Mono.just(savedProcedure));
        when(grantsService.createGrants(anyString(), any())).thenReturn(Mono.just(grantsResult));
        when(credentialOfferService.buildCredentialOffer(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(CredentialOfferData.builder().build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any())).thenReturn(Mono.just("cache-nonce"));
        when(credentialOfferService.createCredentialOfferUriResponse(anyString())).thenReturn(Mono.just("offer-uri"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "Org")));
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://wallet.example.com");
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential(processId, request, idToken))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verify(credentialDataSetBuilderService).buildDataSet(anyString(), eq(request));
        verify(issuanceService).createIssuance(creationRequest);
        verify(grantsService).createGrants(anyString(), any());
        verify(emailService).sendCredentialOfferEmail(eq("test@example.com"), anyString(), eq("offer-uri"), anyString(), eq("https://wallet.example.com"), eq("Org"));
    }

    @Test
    void executeShouldRejectUnknownCredentialType() {
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("UnknownType")
                .email("test@example.com")
                .build();

        when(credentialProfileRegistry.getByConfigurationId("UnknownType")).thenReturn(null);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));
        lenient().when(payloadSchemaValidator.validate(anyString(), any())).thenReturn(Mono.empty());
        lenient().when(issuancePdpService.authorize(anyString(), any(), anyString())).thenReturn(Mono.empty());
        lenient().when(credentialDataSetBuilderService.buildDataSet(anyString(), any())).thenReturn(Mono.empty());

        StepVerifier.create(workflow.issueCredential("p", request, "idToken"))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();
    }

    @Test
    void issueCredentialWithoutAuthorizationShouldSkipPdp() {
        String configId = "LEARCredentialEmployee";
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();

        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId(configId)
                .payload(payload)
                .email("test@example.com")
                .build();

        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();

        IssuanceCreationRequest creationRequest = IssuanceCreationRequest.builder()
                .issuanceId(issuanceId.toString())
                .credentialType(configId)
                .email("test@example.com")
                .delivery("email")
                .build();

        Issuance savedProcedure = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-123")
                .build();

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode("pre-auth")
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .build())
                .build();

        when(credentialProfileRegistry.getByConfigurationId(configId)).thenReturn(profile);
        when(payloadSchemaValidator.validate(anyString(), any())).thenReturn(Mono.empty());
        when(credentialDataSetBuilderService.buildDataSet(anyString(), eq(request))).thenReturn(Mono.just(creationRequest));
        when(issuanceService.createIssuance(creationRequest)).thenReturn(Mono.just(savedProcedure));
        when(grantsService.createGrants(anyString(), any())).thenReturn(Mono.just(new GrantsResult(grants, "5678")));
        when(credentialOfferService.buildCredentialOffer(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(CredentialOfferData.builder().build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any())).thenReturn(Mono.just("nonce"));
        when(credentialOfferService.createCredentialOfferUriResponse(anyString())).thenReturn(Mono.just("offer-uri"));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "Org")));
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://wallet.example.com");
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }
}
