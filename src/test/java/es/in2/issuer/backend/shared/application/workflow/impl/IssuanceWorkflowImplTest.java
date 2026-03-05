package es.in2.issuer.backend.shared.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.*;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
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
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class IssuanceWorkflowImplTest {

    @Mock
    private CredentialDataSetBuilderService credentialDataSetBuilderService;
    @Mock
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private GrantsService grantsService;
    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;
    @Mock
    private DeliveryService deliveryService;
    @Mock
    private IssuancePdpService issuancePdpService;
    @Mock
    private PayloadSchemaValidator payloadSchemaValidator;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private IssuanceMetrics issuanceMetrics;

    @InjectMocks
    private IssuanceWorkflowImpl workflow;

    @Test
    void executeShouldCompleteFullIssuanceFlow() {
        String processId = "test-process";
        String configId = "LEARCredentialEmployee";
        String token = "bearer-token";
        String idToken = "id-token";
        JsonNode payload = new ObjectMapper().createObjectNode().put("name", "Test");
        UUID procedureId = UUID.randomUUID();

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

        CredentialProcedureCreationRequest creationRequest = CredentialProcedureCreationRequest.builder()
                .procedureId(procedureId.toString())
                .credentialType(configId)
                .email("test@example.com")
                .delivery("email")
                .build();

        CredentialProcedure savedProcedure = CredentialProcedure.builder()
                .procedureId(procedureId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .refreshToken("refresh-token-123")
                .build();

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode("pre-auth-code")
                        .txCode(TxCode.builder().length(4).inputMode("numeric").build())
                        .build())
                .authorizationCode(AuthorizationCodeGrant.builder().issuerState("state").build())
                .build();
        GrantsResult grantsResult = new GrantsResult(grants, "1234");

        when(credentialProfileRegistry.getByConfigurationId(configId)).thenReturn(profile);
        when(payloadSchemaValidator.validate(anyString(), any())).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(anyString(), anyString(), any(), anyString())).thenReturn(Mono.empty());
        when(credentialDataSetBuilderService.buildDataSet(anyString(), eq(request))).thenReturn(Mono.just(creationRequest));
        when(credentialProcedureService.createCredentialProcedure(creationRequest)).thenReturn(Mono.just(savedProcedure));
        when(deferredCredentialMetadataService.createDeferredCredentialMetadata(procedureId.toString())).thenReturn(Mono.just("tx-code"));
        when(grantsService.generateGrants(anyString(), any())).thenReturn(Mono.just(grantsResult));
        when(deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(anyString(), anyString())).thenReturn(Mono.empty());
        when(credentialOfferService.buildCredentialOffer(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(CredentialOfferData.builder().build()));
        when(credentialOfferCacheRepository.saveCustomCredentialOffer(any())).thenReturn(Mono.just("cache-nonce"));
        when(credentialOfferService.createCredentialOfferUriResponse(anyString())).thenReturn(Mono.just("offer-uri"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "Org")));
        when(deliveryService.deliver(anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.execute(processId, request, token, idToken))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verify(credentialDataSetBuilderService).buildDataSet(anyString(), eq(request));
        verify(credentialProcedureService).createCredentialProcedure(creationRequest);
        verify(grantsService).generateGrants(anyString(), any());
        verify(deliveryService).deliver(eq("email"), eq("offer-uri"), eq("refresh-token-123"), any());
    }

    @Test
    void executeShouldRejectMissingEmail() {
        PreSubmittedCredentialDataRequest request = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("LEARCredentialEmployee")
                .build();

        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));
        lenient().when(payloadSchemaValidator.validate(anyString(), any())).thenReturn(Mono.empty());
        lenient().when(issuancePdpService.authorize(anyString(), anyString(), any(), anyString())).thenReturn(Mono.empty());
        lenient().when(credentialDataSetBuilderService.buildDataSet(anyString(), any())).thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute("p", request, "token", "idToken"))
                .expectError(IllegalArgumentException.class)
                .verify();
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
        lenient().when(issuancePdpService.authorize(anyString(), anyString(), any(), anyString())).thenReturn(Mono.empty());
        lenient().when(credentialDataSetBuilderService.buildDataSet(anyString(), any())).thenReturn(Mono.empty());

        StepVerifier.create(workflow.execute("p", request, "token", "idToken"))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();
    }

    @Test
    void executeWithoutAuthorizationShouldSkipPdp() {
        String configId = "LEARCredentialEmployee";
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID procedureId = UUID.randomUUID();

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

        CredentialProcedureCreationRequest creationRequest = CredentialProcedureCreationRequest.builder()
                .procedureId(procedureId.toString())
                .credentialType(configId)
                .email("test@example.com")
                .delivery("email")
                .build();

        CredentialProcedure savedProcedure = CredentialProcedure.builder()
                .procedureId(procedureId)
                .refreshToken("refresh-123")
                .build();

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode("pre-auth")
                        .txCode(TxCode.builder().length(4).inputMode("numeric").build())
                        .build())
                .build();

        when(credentialProfileRegistry.getByConfigurationId(configId)).thenReturn(profile);
        when(payloadSchemaValidator.validate(anyString(), any())).thenReturn(Mono.empty());
        when(credentialDataSetBuilderService.buildDataSet(anyString(), eq(request))).thenReturn(Mono.just(creationRequest));
        when(credentialProcedureService.createCredentialProcedure(creationRequest)).thenReturn(Mono.just(savedProcedure));
        when(deferredCredentialMetadataService.createDeferredCredentialMetadata(procedureId.toString())).thenReturn(Mono.just("tx-code"));
        when(grantsService.generateGrants(anyString(), any())).thenReturn(Mono.just(new GrantsResult(grants, "5678")));
        when(deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(anyString(), anyString())).thenReturn(Mono.empty());
        when(credentialOfferService.buildCredentialOffer(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(CredentialOfferData.builder().build()));
        when(credentialOfferCacheRepository.saveCustomCredentialOffer(any())).thenReturn(Mono.just("nonce"));
        when(credentialOfferService.createCredentialOfferUriResponse(anyString())).thenReturn(Mono.just("offer-uri"));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "Org")));
        when(deliveryService.deliver(anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        StepVerifier.create(workflow.executeWithoutAuthorization("p", request))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }
}
