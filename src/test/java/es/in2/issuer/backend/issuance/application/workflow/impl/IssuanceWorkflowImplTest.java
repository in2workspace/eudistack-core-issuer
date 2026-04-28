package es.in2.issuer.backend.issuance.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.PayloadSchemaValidator;
import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.StatusListEntry;
import es.in2.issuer.backend.statuslist.domain.model.StatusListFormat;
import es.in2.issuer.backend.statuslist.domain.model.StatusPurpose;
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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceWorkflowImplTest {

    private static final String BASE_URL = "https://test.example/issuer";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String EMAIL = "test@example.com";

    @Mock private IssuanceService issuanceService;
    @Mock private CredentialOfferService credentialOfferService;
    @Mock private IssuancePdpService issuancePdpService;
    @Mock private PayloadSchemaValidator payloadSchemaValidator;
    @Mock private CredentialProfileRegistry credentialProfileRegistry;
    @Mock private IssuanceMetrics issuanceMetrics;
    @Mock private AuditService auditService;
    @Mock private GenericCredentialBuilder genericCredentialBuilder;
    @Mock private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock private StatusListWorkflow statusListWorkflow;

    @InjectMocks
    private IssuanceWorkflowImpl workflow;

    // --- Existing tests ---

    @Test
    void executeShouldCompleteFullIssuanceFlowWithEmailDelivery() {
        JsonNode payload = new ObjectMapper().createObjectNode().put("name", "Test");
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri");

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(CONFIG_ID, payload, "id-token")).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), eq("authorization_code"),
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL))
                .assertNext(response -> {
                    assertNotNull(response.credentialOfferUri());
                    assertNull(response.signedCredential());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(any(Issuance.class));
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), eq("authorization_code"),
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL));
    }

    @Test
    void executeShouldRejectUnknownCredentialType() {
        IssuanceRequest request = new IssuanceRequest("UnknownType", new ObjectMapper().createObjectNode(), null, EMAIL, null);
        when(credentialProfileRegistry.getByConfigurationId("UnknownType")).thenReturn(null);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "idToken", BASE_URL))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();
    }

    @Test
    void issueCredentialWithoutAuthorizationShouldSkipPdp() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("refresh-token-456").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, BASE_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }

    // --- New tests ---

    @Test
    void directDeliveryShouldSignAndReturnCredentialWithValidStatusWhenValidFromIsPast() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        StatusListEntry statusEntry = statusListEntry();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), isNull(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq("enriched-data-set"), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(isNull(), eq("enriched-with-status"), eq(CONFIG_ID),
                anyString(), isNull(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNull(response.credentialOfferUri());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.VALID));
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void directDeliveryShouldSignAndReturnCredentialWithIssuedStatusWhenValidFromIsFuture() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().plusSeconds(86400));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), isNull(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(isNull(), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.ISSUED));
    }

    @Test
    void directDeliveryShouldFailWhenCnfIsRequired() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
    }

    @Test
    void combinedDirectAndEmailDeliveryShouldRunBothFlowsAndReturnBothResults() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        UUID oid4vciIssuanceId = UUID.randomUUID();
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(oid4vciIssuanceId).credentialOfferRefreshToken("rt-123").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        // Direct flow mocks
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), isNull(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(isNull(), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        // OID4VCI flow mocks
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(oid4vciIssuanceId.toString()), any(), any(), any(), eq("email"), eq("rt-123"), eq(BASE_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNotNull(response.credentialOfferUri());
                })
                .verifyComplete();

        verify(issuanceService, times(2)).saveIssuance(any(Issuance.class));
        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(), any(), any(), any());
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void uiDeliveryShouldReturnCredentialOfferUriWithoutSignedCredential() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-ui").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), any(), eq(EMAIL), eq("ui"), eq("rt-ui"), eq(BASE_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL))
                .assertNext(response -> {
                    assertNotNull(response.credentialOfferUri());
                    assertNull(response.signedCredential());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.DRAFT));
        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
    }

    @Test
    void bootstrapWithDirectDeliveryShouldIgnoreDirectAndRunOid4vciFlow() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-bootstrap").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, BASE_URL))
                .assertNext(response -> assertNull(response.signedCredential()))
                .verifyComplete();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), eq("email"), any(), any());
    }

    @Test
    void issueCredentialShouldFailWithMissingIdTokenWhenProfileRequiresIt() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "VerifiableCertification"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of("RequireCertificationIssuance"))
                        .build())
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(workflow.issueCredential("p", request, null, BASE_URL))
                .expectError(MissingIdTokenHeaderException.class)
                .verify();
    }

    // --- Helpers ---

    private CredentialProfile profileWithoutCnf() {
        return CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
    }

    private CredentialBuildResult buildResult(Instant validFrom) {
        return new CredentialBuildResult(
                "{\"credential\":\"data\"}",
                "did:key:subject",
                "ORGID",
                Timestamp.from(validFrom),
                Timestamp.from(validFrom.plusSeconds(86400 * 365)));
    }

    private StatusListEntry statusListEntry() {
        return StatusListEntry.builder()
                .id("https://status-list/1#42")
                .type("BitstringStatusListEntry")
                .statusPurpose(StatusPurpose.REVOCATION)
                .statusListIndex("42")
                .statusListCredential("https://status-list/1")
                .build();
    }
}
