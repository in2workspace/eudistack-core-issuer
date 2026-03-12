package es.in2.issuer.backend.issuance.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceWorkflowImplTest {

    @Mock
    private IssuanceService issuanceService;
    @Mock
    private CredentialOfferService credentialOfferService;
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
    @Mock
    private GenericCredentialBuilder genericCredentialBuilder;

    @InjectMocks
    private IssuanceWorkflowImpl workflow;

    @Test
    void executeShouldCompleteFullIssuanceFlowWithEmailDelivery() {
        // Given
        String processId = "test-process";
        String configId = "learcredential.employee.w3c.4";
        String idToken = "id-token";
        JsonNode payload = new ObjectMapper().createObjectNode().put("name", "Test");
        UUID issuanceId = UUID.randomUUID();

        IssuanceRequest request = new IssuanceRequest(configId, payload, "email", "test@example.com", null);

        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();

        Timestamp now = Timestamp.from(Instant.now());
        Timestamp later = Timestamp.from(Instant.now().plusSeconds(86400));
        CredentialBuildResult buildResult = new CredentialBuildResult(
                "{\"credential\":\"data\"}", "did:key:subject", "ORGID", now, later);

        Issuance savedIssuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-123")
                .build();

        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri");

        when(credentialProfileRegistry.getByConfigurationId(configId)).thenReturn(profile);
        when(payloadSchemaValidator.validate(configId, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(configId, payload, idToken)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(configId), eq("authorization_code"),
                eq("test@example.com"), eq("email"), eq("refresh-token-123")))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        // When & Then
        StepVerifier.create(workflow.issueCredential(processId, request, idToken))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verify(genericCredentialBuilder).buildCredential(profile, payload);
        verify(issuanceService).saveIssuance(any(Issuance.class));
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(configId), eq("authorization_code"),
                eq("test@example.com"), eq("email"), eq("refresh-token-123"));
    }

    @Test
    void executeShouldRejectUnknownCredentialType() {
        // Given
        IssuanceRequest request = new IssuanceRequest(
                "UnknownType", new ObjectMapper().createObjectNode(), null, "test@example.com", null);

        when(credentialProfileRegistry.getByConfigurationId("UnknownType")).thenReturn(null);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        // When & Then
        StepVerifier.create(workflow.issueCredential("p", request, "idToken"))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();
    }

    @Test
    void issueCredentialWithoutAuthorizationShouldSkipPdp() {
        // Given
        String configId = "learcredential.employee.w3c.4";
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();

        IssuanceRequest request = new IssuanceRequest(configId, payload, "email", "test@example.com", null);

        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();

        Timestamp now = Timestamp.from(Instant.now());
        Timestamp later = Timestamp.from(Instant.now().plusSeconds(86400));
        CredentialBuildResult buildResult = new CredentialBuildResult(
                "{\"credential\":\"data\"}", "did:key:subject", "ORGID", now, later);

        Issuance savedIssuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-456")
                .build();

        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri");

        when(credentialProfileRegistry.getByConfigurationId(configId)).thenReturn(profile);
        when(payloadSchemaValidator.validate(configId, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(configId), eq("authorization_code"),
                eq("test@example.com"), eq("email"), eq("refresh-token-456")))
                .thenReturn(Mono.just(offerResult));

        // When & Then
        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }
}
