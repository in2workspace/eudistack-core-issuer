package es.in2.issuer.backend.issuance.application.workflow.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.application.workflow.CredentialSignerWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.exception.MissingIdTokenHeaderException;
import es.in2.issuer.backend.shared.domain.exception.TenantNotResolvedException;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidHolderKeyException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.DeliveryTrace;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.policy.service.IssuancePdpService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.CredentialIssuedLogger;
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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IssuanceWorkflowImplTest {

    private static final String BASE_URL = "https://test.example/issuer";
    private static final String WALLET_URL = "https://test.example/wallet";
    private static final String CONFIG_ID = "learcredential.employee.w3c.4";
    private static final String EMAIL = "test@example.com";
    private static final String TENANT_ID = "sandbox";
    private static final int HYBRID_WALLET_TIMEOUT_SECONDS = 1;

    /**
     * Every call below simulates a request that already went through {@code TenantDomainWebFilter}
     * with a resolved tenant (EUD-170: {@code issueCredential} now fails closed without one).
     * Tenant-specific behavior itself (fail-closed, attribution) is covered separately below.
     */
    private static <T> Mono<T> withTenant(Mono<T> mono) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT_ID));
    }

    @Mock private IssuanceService issuanceService;
    @Mock private CredentialOfferService credentialOfferService;
    @Mock private IssuancePdpService issuancePdpService;
    @Mock private PayloadSchemaValidator payloadSchemaValidator;
    @Mock private CredentialProfileRegistry credentialProfileRegistry;
    @Mock private IssuanceMetrics issuanceMetrics;
    @Mock private CredentialIssuedLogger credentialIssuedLogger;
    @Mock private AuditService auditService;
    @Mock private GenericCredentialBuilder genericCredentialBuilder;
    @Mock private CredentialSignerWorkflow credentialSignerWorkflow;
    @Mock private StatusListWorkflow statusListWorkflow;

    @Spy
    private IssuanceProperties issuanceProperties =
            new IssuanceProperties(30, "0 0 2 * * *", 60, "0 */5 * * * ?", HYBRID_WALLET_TIMEOUT_SECONDS);

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
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertNotNull(response.credentialOfferUri());
                    assertNull(response.signedCredential());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(any(Issuance.class));
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), eq("authorization_code"),
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL));
        // A wallet offer is not an emitted credential — only the OID4VCI /credential endpoint
        // (where the wallet actually collects it) counts this leg.
        verify(credentialIssuedLogger, never()).logIssued(any());
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void executeShouldRejectUnknownCredentialType() {
        IssuanceRequest request = new IssuanceRequest("UnknownType", new ObjectMapper().createObjectNode(), null, EMAIL, null);
        when(credentialProfileRegistry.getByConfigurationId("UnknownType")).thenReturn(null);
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "idToken", BASE_URL, WALLET_URL)))
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
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }

    // --- New tests ---

    @Test
    void directDeliveryShouldSucceedWhenIdTokenIsAbsent() {
        // Regression: X-Id-Token is optional (only profiles carrying RequireCertificationIssuance
        // demand it -- see issueCredentialShouldFailWithMissingIdTokenWhenProfileRequiresIt), yet
        // performDirectIssuance forwards it as the caller token to the status list and to signing.
        // Both used to reject a null, so a direct issuance without the header returned a 500.
        //
        // NOTE: this test alone would NOT have caught that bug -- StatusListWorkflow is mocked
        // here, and it was the real BitstringStatusListProvider that threw. It pins the wiring
        // (null must flow through untouched); the guard itself is pinned by
        // BitstringStatusListProviderTest#allocateEntry_shouldAllocateAndCreateList_whenTokenIsNull
        // and end-to-end by DirectIssuanceIT. The three are complements, not duplicates.
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        StatusListEntry statusEntry = statusListEntry();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), isNull())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        // isNull(), not anyString(): anyString() does not match null, and a non-matching stub
        // would return null and fail the test for the wrong reason.
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

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, null, BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

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
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusEntry));
        when(genericCredentialBuilder.injectCredentialStatus(eq("enriched-data-set"), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), eq("enriched-with-status"), eq(CONFIG_ID),
                anyString(), isNull(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNull(response.credentialOfferUri());
                    assertNotNull(response.deliveryResults());
                    assertEquals(1, response.deliveryResults().size());
                    assertEquals("direct", response.deliveryResults().get(0).mode());
                    assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED, response.deliveryResults().get(0).status());
                    assertNull(response.deliveryResults().get(0).error());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.VALID));
        verifyNoInteractions(credentialOfferService);
        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
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
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.ISSUED));
    }

    @Test
    void directDeliveryOfBearerTypeWithoutHolderKeyShouldSignWithoutCnf() {
        // Third corner of the binding matrix (EUD-33): no cryptographic binding method AND
        // cnf_required=false. Nothing supplies a holder key and nothing needs one -- the request
        // carries none, the flow demands none, and the credential is signed with a null cnf.
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(),
                anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(), isNull(), any(), any());
        ArgumentCaptor<Issuance> persisted = ArgumentCaptor.forClass(Issuance.class);
        verify(issuanceService).saveIssuance(persisted.capture());
        assertNull(persisted.getValue().getHolderCnf());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithConfigButNoHolderKeyShouldFailWith400() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeNotEligibleShouldFailEvenWithValidHolderKey() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = walletBoundProfileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(DeliveryModeNotEligibleException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithHolderKeyShouldSignWithCnfAndPersist() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), eq("enriched-with-status"), eq(CONFIG_ID),
                anyString(), anyMap(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> cnfCaptor = ArgumentCaptor.forClass(Map.class);
        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(),
                cnfCaptor.capture(), any(), any());
        assertNotNull(cnfCaptor.getValue());
        assertTrue(cnfCaptor.getValue().containsKey("jwk"));
        verify(issuanceService).saveIssuance(any(Issuance.class));
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void directDeliveryOfCnfRequiredTypeWithAmbiguousHolderKeyShouldFailWith400() {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode payload = mapper.createObjectNode();
        JsonNode ambiguous = mapper.createObjectNode()
                .put("kid", "did:key:z6Mk#key-1");
        ((com.fasterxml.jackson.databind.node.ObjectNode) ambiguous)
                .set("jwk", mapper.createObjectNode().put("kty", "EC"));
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, ambiguous);
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfNonCnfTypeShouldNotInjectCnfEvenIfHolderKeyPresent() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithoutCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(),
                anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(), isNull(), any(), any());
    }

    @Test
    void walletOnlyDeliveryOfWalletBoundTypeShouldNotRequireHolderKey() {
        // The wallet proves possession of its own key at the credential endpoint, so the request
        // supplies nothing. This is the ONLY shape that exempts a cnf-required type from carrying
        // a holder_key -- see the test right below for the one that does not.
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = walletBoundProfileWithCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri");

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), anyString(), eq(EMAIL), eq("email"),
                eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        verifyNoInteractions(credentialSignerWorkflow);
    }

    @Test
    void walletOnlyDeliveryOfHolderKeyRequiredTypeShouldFailWithoutHolderKey() {
        // Reverses EUD-168 EC-04: the holder key requirement is a property of the credential type,
        // not of the direct mode. A type with no cryptographic binding method gets no wallet proof
        // either, so an email/ui issuance without a holder_key has no cnf source at all.
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(InvalidHolderKeyException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void walletOnlyDeliveryOfHolderKeyRequiredTypeShouldPersistTheCnfForTheCredentialEndpoint() {
        // The credential endpoint is a separate HTTP call with no proof to derive a cnf from, so the
        // key supplied at intake must survive in the Issuance for it to read back.
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri");

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), anyString(), eq(EMAIL), eq("email"),
                eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        ArgumentCaptor<Issuance> persisted = ArgumentCaptor.forClass(Issuance.class);
        verify(issuanceService).saveIssuance(persisted.capture());
        assertEquals("{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x-coord\",\"y\":\"y-coord\"}}",
                persisted.getValue().getHolderCnf());
    }

    @Test
    void hybridDeliveryOfCnfRequiredTypeShouldSignDirectWithCnfAndDispatchWallet() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        UUID issuanceId = UUID.randomUUID();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId)
                .credentialOfferRefreshToken("refresh-token-123").build();
        CredentialOfferResult offerResult = new CredentialOfferResult("openid-credential-offer://offer-uri");

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(),
                anyString(), anyMap(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq(CONFIG_ID), anyString(), eq(EMAIL), eq("email"),
                eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNotNull(response.credentialOfferUri());
                })
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(
                any(), any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeShouldFailClosedWhenSignerFails() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), anyMap(), any(), any()))
                .thenReturn(Mono.error(new IllegalStateException("signer down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        // AC-06: the direct leg is materialized now, so the failure surfaces as DeliveryFailedException
        // with the original cause attached, not as the raw signer error.
        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(DeliveryFailedException.class, error);
                    assertInstanceOf(IllegalStateException.class, error.getCause());
                    DeliveryFailedException failure = (DeliveryFailedException) error;
                    assertEquals(1, failure.deliveryResults().size());
                    assertEquals("direct", failure.deliveryResults().getFirst().mode());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, failure.deliveryResults().getFirst().status());
                })
                .verify();

        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void directDeliveryOfCnfRequiredTypeShouldFailClosedWhenPersistenceFails() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null, holderKeyJwk());
        CredentialProfile profile = profileWithCnf();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), anyMap(), any(), any()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class)))
                .thenReturn(Mono.error(new IllegalStateException("db down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectErrorSatisfies(error -> {
                    assertInstanceOf(DeliveryFailedException.class, error);
                    assertInstanceOf(IllegalStateException.class, error.getCause());
                })
                .verify();
    }


    @Test
    void issueCredentialShouldFailWithInvalidDeliveryModeWhenModeIsUnknown() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,carrier-pigeon", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(InvalidDeliveryModeException.class)
                .verify();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow, credentialOfferService);
        verify(issuanceService, never()).saveIssuance(any());
    }

    @Test
    void issueCredentialShouldFailWithInvalidDeliveryModeWhenModeIsBlank() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "   ", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(InvalidDeliveryModeException.class)
                .verify();

        verify(issuanceService, never()).saveIssuance(any());
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
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        // OID4VCI flow mocks
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(oid4vciIssuanceId.toString()), any(), any(), any(), eq("email"), eq("rt-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNotNull(response.credentialOfferUri());
                    assertNotNull(response.deliveryResults());
                    assertTrue(response.deliveryResults().stream().anyMatch(r ->
                            "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DELIVERED));
                    assertTrue(response.deliveryResults().stream().anyMatch(r ->
                            "email".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DISPATCHED));
                })
                .verifyComplete();

        verify(issuanceService, times(2)).saveIssuance(any(Issuance.class));
        verify(credentialSignerWorkflow).signCredential(any(), any(), any(), any(), any(), any(), any());
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any());
        // Exactly one credential is emitted here (the direct leg); the wallet leg only creates a
        // DRAFT + sends an offer, so it must not add a second increment.
        verify(credentialIssuedLogger, times(1)).logIssued(CONFIG_ID);
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
                eq(issuanceId.toString()), eq(CONFIG_ID), any(), eq(EMAIL), eq("ui"), eq("rt-ui"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertNotNull(response.credentialOfferUri());
                    assertNull(response.signedCredential());
                    assertNotNull(response.deliveryResults());
                    assertEquals(1, response.deliveryResults().size());
                    assertEquals("ui", response.deliveryResults().get(0).mode());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, response.deliveryResults().get(0).status());
                })
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.DRAFT));
        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
        verify(credentialIssuedLogger, never()).logIssued(any());
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
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
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNull(response.signedCredential()))
                .verifyComplete();

        verifyNoInteractions(credentialSignerWorkflow, statusListWorkflow);
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), eq("email"), any(), any(), any());
        // Bootstrap strips "direct" and never signs anything.
        verify(credentialIssuedLogger, never()).logIssued(any());
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

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, null, BASE_URL, WALLET_URL)))
                .expectError(MissingIdTokenHeaderException.class)
                .verify();
    }

    @Test
    void issueCredentialWithoutAuthorizationShouldUseDefaultEmailDeliveryWhenDeliveryIsNull() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, null, EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-null-delivery").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        verifyNoInteractions(issuancePdpService);
    }

    @Test
    void issueCredentialShouldPassValidationWhenProfileRequiresIdTokenAndTokenIsProvided() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "VerifiableCertification"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of("RequireCertificationIssuance"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-cert").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();
    }

    @Test
    void validateRequestShouldPassWhenIssuancePolicyHasNullRules() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(null)
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-null-rules").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();
    }

    @Test
    void directDeliveryShouldReturnValidStatusWhenValidFromIsNull() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = CredentialBuildResult.builder()
                .credentialDataSet("{\"credential\":\"data\"}")
                .subject("did:key:subject")
                .organizationIdentifier("ORGID")
                .validFrom(null)
                .validUntil(null)
                .build();
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(StatusListFormat.class),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(issuanceService).saveIssuance(argThat(i -> i.getCredentialStatus() == CredentialStatusEnum.VALID));
    }

    @Test
    void directDeliveryShouldUseDefaultJwtVcJsonFormatWhenProfileFormatIsNull() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format(null)
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.BITSTRING_VC),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.BITSTRING_VC),
                anyString(), anyString(), eq(BASE_URL));
    }

    @Test
    void directDeliveryShouldUseTokenJwtStatusFormatForDcSdJwtCredential() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("dc+sd-jwt")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.TOKEN_JWT),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();

        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.TOKEN_JWT),
                anyString(), anyString(), eq(BASE_URL));
    }

    @Test
    void oid4vciIssuanceShouldUseProvidedGrantTypeWhenNotNull() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-grant").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                any(), eq(CONFIG_ID), eq("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                eq(EMAIL), eq("email"), eq("rt-grant"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(
                any(), any(), eq("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                any(), any(), any(), any(), any());
    }

    @Test
    void validateRequestShouldPassWhenIssuancePolicyHasRulesWithoutRequiredRule() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of("SomeOtherRule"))
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt-other-rule").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "token", BASE_URL, WALLET_URL))
                .assertNext(response -> assertNotNull(response))
                .verifyComplete();
    }

    @Test
    void directIssuanceOfDcSdJwtProfileShouldPersistTheProfileCredentialFormat() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("dc+sd-jwt")
                .cnfRequired(false)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .sdJwt(CredentialProfile.SdJwtConfig.builder()
                        .vct("LEARCredentialEmployee")
                        .sdAlg("sha-256")
                        .build())
                .build();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), eq(StatusListFormat.TOKEN_JWT),
                anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), eq("dc+sd-jwt")))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), eq(CONFIG_ID),
                eq("dc+sd-jwt"), isNull(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("signed-sd-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-sd-jwt", response.signedCredential()))
                .verifyComplete();

        // AC-04: the SD-JWT VC credential is persisted with the profile's format, not a
        // default format or another branch's.
        verify(issuanceService).saveIssuance(argThat(i -> "dc+sd-jwt".equals(i.getCredentialFormat())));
    }

    @Test
    void oid4vciIssuanceShouldPersistTheCatalogueConfigurationIdAsCredentialType() {
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialOfferRefreshToken("rt-conformance")
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertNotNull(response.credentialOfferUri()))
                .verifyComplete();

        // AC-04: the credential_configuration_id sent matches exactly the resolved catalog
        // profile -- no intermediate rewrites on the persisted entity.
        verify(issuanceService).saveIssuance(argThat(i -> CONFIG_ID.equals(i.getCredentialType())));
    }

    @Test
    void hybridDeliveryWalletFailureShouldKeepDirectDelivered() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    assertNull(response.credentialOfferUri());
                    DeliveryResult direct = deliveryResultFor(response, "direct");
                    DeliveryResult email = deliveryResultFor(response, "email");
                    assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED, direct.status());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, email.status());
                    assertNotNull(email.error());
                })
                .verifyComplete();

        // Mono.zip isolation: the wallet leg's failure (swallowed by
        // performOid4VciIssuanceResilient) must not affect the direct leg's counter.
        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void hybridDeliveryWalletTimeoutShouldKeepDirectDelivered() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        // Wallet path never completes within the hybrid budget (HYBRID_WALLET_TIMEOUT_SECONDS = 1s).
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("offer")).delayElement(Duration.ofSeconds(30)));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("signed-jwt", response.signedCredential());
                    DeliveryResult email = deliveryResultFor(response, "email");
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, email.status());
                    assertEquals("Wallet delivery timed out", email.error());
                    assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED, deliveryResultFor(response, "direct").status());
                })
                .verifyComplete();

        verify(credentialIssuedLogger).logIssued(CONFIG_ID);
        verify(credentialIssuedLogger, never()).logFailed(any(), any());
    }

    @Test
    void directDeliverySignerFailureShouldFailClosed() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("QTSP down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(RuntimeException.class)
                .verify();

        verify(issuanceService, never()).saveIssuance(any());
        verify(credentialIssuedLogger).logFailed(eq(CONFIG_ID), any());
        verify(credentialIssuedLogger, never()).logIssued(any());
    }

    @Test
    void hybridDirectResultShouldBeIdenticalForEmailAndUiChannels() {
        String signedEmail = runHybridAndCaptureSignedCredential("direct,email", "email");
        String signedUi = runHybridAndCaptureSignedCredential("direct,ui", "ui");

        assertEquals("signed-jwt", signedEmail);
        assertEquals(signedEmail, signedUi);
    }

    private String runHybridAndCaptureSignedCredential(String delivery, String expectedWalletChannel) {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, delivery, EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), eq(expectedWalletChannel), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        IssuanceResponse response = withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)).block();
        assertNotNull(response);
        verify(credentialOfferService).createAndDeliverCredentialOffer(any(), any(), any(), any(), eq(expectedWalletChannel), any(), any(), any());
        return response.signedCredential();
    }

    @Test
    void directDeliveryShouldInjectStatusPointerAndPersistBeforeDelivered() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(eq(StatusPurpose.REVOCATION), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(eq("enriched-data-set"), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), eq("enriched-with-status"), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals(DeliveryResult.DeliveryOutcome.DELIVERED,
                        deliveryResultFor(response, "direct").status()))
                .verifyComplete();

        verify(statusListWorkflow).allocateEntry(eq(StatusPurpose.REVOCATION), any(), anyString(), anyString(), eq(BASE_URL));
        verify(genericCredentialBuilder).injectCredentialStatus(eq("enriched-data-set"), any(), anyString());
        verify(issuanceService).saveIssuance(argThat(i ->
                i.getCredentialStatus() == CredentialStatusEnum.VALID
                        && "enriched-with-status".equals(i.getCredentialDataSet())));
    }

    @Test
    void directDeliveryPersistenceFailureShouldFailClosed() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.error(new RuntimeException("DB down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(RuntimeException.class)
                .verify();

        verify(credentialIssuedLogger).logFailed(eq(CONFIG_ID), any());
        verify(credentialIssuedLogger, never()).logIssued(any());
    }

    @Test
    void auditDeliveryShouldIncludeDeliveryResultsTenantAndNoRecipientEmail() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertEquals(TENANT_ID, trace.tenantId());
        assertEquals("p", trace.processId());
        assertFalse(trace.hasFailure());
        assertTrue(trace.results().stream().anyMatch(r ->
                "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DELIVERED));
        assertFalse(trace.toString().contains(EMAIL), "delivery trace must not leak recipient email");
    }

    @Test
    void auditDeliveryShouldEmitFailedTraceOnSignerError() {
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.error(new RuntimeException("QTSP down")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectError(RuntimeException.class)
                .verify();

        // EUD-170 AC-03: the failure path knew which mode failed, so the trace says "direct", not
        // "unknown". The indeterminate trace of ES-01 is reserved for failures that ran no mode at all.
        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertEquals(TENANT_ID, trace.tenantId());
        assertTrue(trace.hasFailure());
        assertTrue(trace.results().stream().anyMatch(r ->
                "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.FAILED));
        assertTrue(trace.results().stream().noneMatch(r -> "unknown".equals(r.mode())));
    }

    @Test
    void issueCredentialShouldFailClosedWhenTenantIsNotResolved() {
        // Given (AC-05/ES-02): no tenant in the Reactor context, unlike every other test in this class
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);

        // When / Then
        StepVerifier.create(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL))
                .expectError(TenantNotResolvedException.class)
                .verify();

        // Nothing that runs after tenant resolution (deferred via Mono.defer) ever executed, and
        // no trace was emitted against a default tenant. (credentialProfileRegistry is excluded:
        // validateRequest(...) is evaluated eagerly as a plain method argument before the reactive
        // chain subscribes, so it always runs regardless of the tenant guard's outcome -- a
        // pre-existing trait of this method, unrelated to fail-closed behavior.)
        verifyNoInteractions(auditService, payloadSchemaValidator,
                issuancePdpService, genericCredentialBuilder, credentialSignerWorkflow,
                issuanceService, credentialOfferService);
    }

    @Test
    void auditDeliveryShouldReflectFailureWhenWalletLegFailsInHybridDelivery() {
        // Given (AC-03/EC-02): hybrid delivery, wallet leg fails, direct leg delivers
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance directIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();
        Issuance oid4vciIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() != CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(directIssuance));
        when(issuanceService.saveIssuance(argThat(i -> i != null && i.getCredentialStatus() == CredentialStatusEnum.DRAFT)))
                .thenReturn(Mono.just(oid4vciIssuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertTrue(trace.hasFailure(), "one failed leg in a hybrid delivery must mark the trace as a failure (AC-03)");
        assertTrue(trace.results().stream().anyMatch(r ->
                "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DELIVERED));
        assertTrue(trace.results().stream().anyMatch(r ->
                "email".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.FAILED));
    }

    @Test
    void auditDeliveryShouldContainOnlyWalletModeForWalletOnlyDelivery() {
        // Given (EC-01): wallet-only delivery must not fabricate a direct entry
        JsonNode payload = new ObjectMapper().createObjectNode();
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
                eq(EMAIL), eq("email"), eq("refresh-token-123"), eq(BASE_URL), eq(WALLET_URL)))
                .thenReturn(Mono.just(offerResult));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectNextCount(1)
                .verifyComplete();

        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        DeliveryTrace trace = captor.getValue();
        assertEquals(1, trace.results().size());
        assertEquals("email", trace.results().iterator().next().mode());
        assertFalse(trace.hasFailure());
    }

    @Test
    void issueCredentialShouldCompleteSuccessfullyEvenWhenAuditChannelThrows() {
        // Given (ES-03/ES-04): the credential is already delivered before the audit call is made
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        CredentialBuildResult buildResult = buildResult(Instant.now().minusSeconds(100));
        Issuance savedIssuance = Issuance.builder().issuanceId(UUID.randomUUID()).build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload)).thenReturn(Mono.just(buildResult));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(eq("id-token"), anyString(), anyString(), anyString(), isNull(), anyString(), anyString()))
                .thenReturn(Mono.just("signed-jwt"));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(savedIssuance));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));
        doThrow(new RuntimeException("AUDIT channel down")).when(auditService).auditDelivery(any());

        // Then: a broken audit channel must not surface as a failure of the response the operator receives.
        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals("signed-jwt", response.signedCredential()))
                .verifyComplete();
    }

    // --- AC-06 / EC-05 / ES-07: per-mode result contract and the HTTP status rule ---

    @Test
    void walletOnlyDeliveryTotalFailureShouldFailInsteadOfReportingSuccess() {
        // ES-07: nothing was delivered, so a 200 would assert a delivery that never happened.
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        Issuance saved = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(saved));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("SMTP unavailable")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectErrorSatisfies(error -> {
                    DeliveryFailedException failure = assertInstanceOf(DeliveryFailedException.class, error);
                    assertEquals(1, failure.deliveryResults().size());
                    DeliveryResult email = failure.deliveryResults().getFirst();
                    assertEquals("email", email.mode());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, email.status());
                    assertNotNull(email.error());
                })
                .verify();
    }

    @Test
    void hybridDirectFailureShouldStillReportTheWalletDispatchAndItsOfferInTheError() {
        // AC-06 + ES-02: direct is decisive, so this is an error — but the wallet leg dispatched, and
        // discarding that is what left the caller unable to tell whether an email had gone out. The
        // offer travels too: a dispatched channel is redeemable, and the caller needs the URI to
        // show its QR instead of claiming the offer could not be generated.
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        Issuance saved = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(genericCredentialBuilder.bindIssuer(eq(profile), anyString(), anyString(), eq(EMAIL)))
                .thenReturn(Mono.just("enriched-data-set"));
        when(statusListWorkflow.allocateEntry(any(), any(), anyString(), anyString(), eq(BASE_URL)))
                .thenReturn(Mono.just(statusListEntry()));
        when(genericCredentialBuilder.injectCredentialStatus(anyString(), any(), anyString()))
                .thenReturn("enriched-with-status");
        when(credentialSignerWorkflow.signCredential(any(), any(), any(), any(), isNull(), any(), any()))
                .thenReturn(Mono.error(new RuntimeException("QTSP down")));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(saved));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .expectErrorSatisfies(error -> {
                    DeliveryFailedException failure = assertInstanceOf(DeliveryFailedException.class, error);
                    assertEquals(2, failure.deliveryResults().size());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, resultFor(failure, "direct").status());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, resultFor(failure, "email").status());
                    assertEquals("openid-credential-offer://offer-uri", failure.credentialOfferUri());
                })
                .verify();

        // EUD-170 AC-03: the trace carries both modes, not a single indeterminate entry.
        ArgumentCaptor<DeliveryTrace> captor = ArgumentCaptor.forClass(DeliveryTrace.class);
        verify(auditService).auditDelivery(captor.capture());
        assertTrue(captor.getValue().results().stream().anyMatch(r ->
                "email".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.DISPATCHED));
        assertTrue(captor.getValue().results().stream().anyMatch(r ->
                "direct".equals(r.mode()) && r.status() == DeliveryResult.DeliveryOutcome.FAILED));
    }

    @Test
    void walletDeliveryWithFailedEmailShouldKeepTheQrChannelDispatchedAndTheOfferUri() {
        // EC-05: the offer is cached and redeemable before any transport runs, so an SMTP outage must
        // not condemn the QR channel nor discard the URI the QR needs.
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "email,ui", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        Issuance saved = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt").build();
        CredentialOfferResult partial = CredentialOfferResult.builder()
                .credentialOfferUri("openid-credential-offer://offer-uri")
                .failedModes(Map.of(DeliveryMode.EMAIL, "Error during communication with the mail server"))
                .build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(saved));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(partial));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> {
                    assertEquals("openid-credential-offer://offer-uri", response.credentialOfferUri());
                    assertEquals(DeliveryResult.DeliveryOutcome.FAILED, deliveryResultFor(response, "email").status());
                    assertEquals(DeliveryResult.DeliveryOutcome.DISPATCHED, deliveryResultFor(response, "ui").status());
                    assertNull(deliveryResultFor(response, "ui").error());
                })
                .verifyComplete();
    }

    @Test
    void walletDeliveryResultsShouldFollowStableEnumOrderRegardlessOfRequestOrder() {
        // DeliveryMode.parse collects into a HashSet, whose enum iteration order is identity-hash
        // based. Without the explicit ordering the result order varied between JVM runs.
        UUID issuanceId = UUID.randomUUID();
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "ui,email", EMAIL, null);
        CredentialProfile profile = profileWithoutCnf();
        Issuance saved = Issuance.builder().issuanceId(issuanceId).credentialOfferRefreshToken("rt").build();

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profile);
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());
        when(issuancePdpService.authorize(eq(CONFIG_ID), eq(payload), anyString())).thenReturn(Mono.empty());
        when(genericCredentialBuilder.buildCredential(profile, payload))
                .thenReturn(Mono.just(buildResult(Instant.now().minusSeconds(100))));
        when(issuanceService.saveIssuance(any(Issuance.class))).thenReturn(Mono.just(saved));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(new CredentialOfferResult("openid-credential-offer://offer-uri")));
        when(issuanceMetrics.startTimer()).thenReturn(Timer.start(new SimpleMeterRegistry()));

        StepVerifier.create(withTenant(workflow.issueCredential("p", request, "id-token", BASE_URL, WALLET_URL)))
                .assertNext(response -> assertEquals(List.of("email", "ui"),
                        response.deliveryResults().stream().map(DeliveryResult::mode).toList()))
                .verifyComplete();
    }

    @Test
    void bootstrapWithDirectOnlyDeliveryShouldFailWithInvalidDeliveryMode() {
        // Bootstrap strips `direct`; with nothing left, keepOnlyOid4vciDeliveryModes threw outside the
        // reactive chain, escaping every @ExceptionHandler and surfacing as a 500 instead of a 400.
        JsonNode payload = new ObjectMapper().createObjectNode();
        IssuanceRequest request = new IssuanceRequest(CONFIG_ID, payload, "direct", EMAIL, null);

        when(credentialProfileRegistry.getByConfigurationId(CONFIG_ID)).thenReturn(profileWithoutCnf());
        when(payloadSchemaValidator.validate(CONFIG_ID, payload)).thenReturn(Mono.empty());

        StepVerifier.create(workflow.issueCredentialWithoutAuthorization("p", request, "bootstrap-token", BASE_URL, WALLET_URL))
                .expectError(InvalidDeliveryModeException.class)
                .verify();

        verifyNoInteractions(credentialOfferService, credentialSignerWorkflow);
    }

    // --- Helpers ---

    private DeliveryResult resultFor(DeliveryFailedException failure, String mode) {
        return failure.deliveryResults().stream()
                .filter(r -> mode.equals(r.mode()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No delivery result for mode " + mode));
    }

    private DeliveryResult deliveryResultFor(IssuanceResponse response, String mode) {
        assertNotNull(response.deliveryResults());
        return response.deliveryResults().stream()
                .filter(r -> mode.equals(r.mode()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No delivery result for mode " + mode));
    }

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

    /** Holder-bound, key supplied by the caller: cnf_required with no cryptographic binding method. */
    private CredentialProfile profileWithCnf() {
        return CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
    }

    /** Holder-bound, key supplied by a wallet proof: the only shape that makes direct ineligible. */
    private CredentialProfile walletBoundProfileWithCnf() {
        return CredentialProfile.builder()
                .credentialConfigurationId(CONFIG_ID)
                .format("jwt_vc_json")
                .cnfRequired(true)
                .cryptographicBindingMethodsSupported(Set.of("did:key"))
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(List.of("VerifiableCredential", "LEARCredentialEmployee"))
                        .build())
                .build();
    }

    private JsonNode holderKeyJwk() {
        ObjectMapper m = new ObjectMapper();
        return m.createObjectNode().set("jwk",
                m.createObjectNode().put("kty", "EC").put("crv", "P-256").put("x", "x-coord").put("y", "y-coord"));
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
