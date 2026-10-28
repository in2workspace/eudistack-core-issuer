package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryErrorCode;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.tenantconfig.TenantCustomDomainsLoader;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockitoBean(types = ReactiveAuthenticationManager.class)
@WebFluxTest(IssuanceController.class)
@Import({IssuanceExceptionHandler.class, IssuanceHttpEnvelopeMapper.class})
class IssuanceControllerTest {

    private static final String ISSUANCES_PATH = "/api/v1/issuances";
    private static final String BEARER_TOKEN = "Bearer operator-access-token";
    private static final String PUBLIC_ISSUER_BASE_URL = "https://issuer.example.com";

    @Autowired
    private WebTestClient webTestClient;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private ErrorResponseFactory errorResponseFactory;

    @MockitoBean
    private NonceService nonceService;

    @MockitoBean
    private IssuanceWorkflow issuanceWorkflow;

    @MockitoBean
    private IssuanceService issuanceService;

    /** Not used by the controller any more; other beans of the WebFlux slice still need it. */
    @MockitoBean
    private AccessTokenService accessTokenService;

    @MockitoBean
    private PowerAuthorizationService powerAuthorizationService;

    @MockitoBean
    private RevocationWorkflow revocationWorkflow;

    @MockitoBean
    private IssuanceMetrics issuanceMetrics;

    @MockitoBean
    private TenantRegistryService tenantRegistryService;

    @MockitoBean
    private TenantCustomDomainsLoader tenantCustomDomainsLoader;

    @MockitoBean
    private UrlResolver urlResolver;

    /**
     * EUD-167 D-6/D-5 (AD-1 B) supersedes EUD-168 AD-11's 500: a hybrid issuance whose direct mode
     * failed while the wallet mode dispatched is a mixed outcome, reported as HTTP 207 Multi-Status
     * (RFC 4918 §11.1/§13) with per-mode results and the credential offer URI intact -- not a 500.
     */
    @Test
    void createIssuance_WhenDirectDeliveryFailedInHybrid_Returns207WithPerModeResultsAndOfferUri()
            throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fabc";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(
                                DeliveryResult.failed("direct", DeliveryErrorCode.SIGNING_FAILED.value()),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.MULTI_STATUS)
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("direct")
                .jsonPath("$.responses[0].status").isEqualTo(503)
                .jsonPath("$.responses[0].error.type").isEqualTo("signing_failed")
                .jsonPath("$.responses[0].error.title").isEqualTo("Signing failed")
                .jsonPath("$.responses[0].body").doesNotExist()
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body.credential_offer_uri").isEqualTo(credentialOfferUri)
                .jsonPath("$.responses[1].error").doesNotExist();
    }

    /**
     * The mirror case: a wallet mode failed while the direct mode delivered. Also a mixed outcome
     * under D-5's general rule (at least one 2xx, at least one failure => 207) -- previously 200 under
     * AD-11, which only looked at whether the *direct* mode failed.
     */
    @Test
    void createIssuance_WhenOnlyAWalletModeFailed_Returns207WithPerModeResults() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fabc";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(
                                DeliveryResult.failed("email", DeliveryErrorCode.DELIVERY_FAILED.value()),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.MULTI_STATUS)
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(503)
                .jsonPath("$.responses[0].error.type").isEqualTo("delivery_failed")
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body.credential_offer_uri").isEqualTo(credentialOfferUri);
    }

    /**
     * Every requested channel failed (e.g. the wallet dependency is down for a wallet-only request,
     * so the direct leg was never attempted and assembleOutcome had nothing to re-raise). Not a mixed
     * outcome -- a genuine failure, reported as 500 instead of 200/202.
     */
    @Test
    void createIssuance_WhenAllChannelsFailed_Returns500() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN),
                eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .deliveryResults(List.of(
                                DeliveryResult.failed("email", DeliveryErrorCode.DELIVERY_FAILED.value()),
                                DeliveryResult.failed("ui", DeliveryErrorCode.WALLET_DELIVERY_TIMEOUT.value())))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().is5xxServerError()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(503)
                .jsonPath("$.responses[0].error.type").isEqualTo("delivery_failed")
                // WALLET_DELIVERY_TIMEOUT maps to 504, distinct from the generic 503 (per-channel status).
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(504)
                .jsonPath("$.responses[1].error.type").isEqualTo("wallet_delivery_timeout");
    }

    @Test
    void createIssuance_WhenCredentialOfferUriIsPresent_Returns200WithBody() throws JsonProcessingException {
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2Fabc123";
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("ui")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.credential_offer_uri").isEqualTo(credentialOfferUri)
                .jsonPath("$.responses[0].body.signed_credential").doesNotExist();
    }

    @Test
    void createIssuance_WhenSignedCredentialIsPresent_Returns200WithBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String signedCredential = "signed-credential-value";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .signedCredential(signedCredential)
                        .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("direct")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.signed_credential").isEqualTo(signedCredential)
                .jsonPath("$.responses[0].body.credential_offer_uri").doesNotExist();
    }

    @Test
    void createIssuance_Hybrid_Returns200WithDeliveryResults() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .signedCredential("signed-jwt")
                        .credentialOfferUri("openid-credential-offer://x")
                        .deliveryResults(List.of(
                                DeliveryResult.delivered("direct"),
                                DeliveryResult.dispatched("email"),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("direct")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.signed_credential").isEqualTo("signed-jwt")
                .jsonPath("$.responses[1].channel").isEqualTo("email")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body").doesNotExist()
                .jsonPath("$.responses[2].channel").isEqualTo("ui")
                .jsonPath("$.responses[2].status").isEqualTo(200)
                .jsonPath("$.responses[2].body.credential_offer_uri").isEqualTo("openid-credential-offer://x");
    }

    /** D-5 retires the 202 wallet-only status: a fully successful request is always 200. */
    @Test
    void createIssuance_WalletOnly_Returns200WithDeliveryResultsBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fabc";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .deliveryResults(List.of(
                                DeliveryResult.dispatched("email"),
                                DeliveryResult.dispatched("ui")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body").doesNotExist()
                .jsonPath("$.responses[1].channel").isEqualTo("ui")
                .jsonPath("$.responses[1].status").isEqualTo(200)
                .jsonPath("$.responses[1].body.credential_offer_uri").isEqualTo(credentialOfferUri)
                .jsonPath("$.responses[1].body.signed_credential").doesNotExist();
    }

    /**
     * TD-06 (code-review): the {@code delivery} field is rejected at Bean Validation, before
     * {@code IssuanceWorkflow} ever runs -- the request never even reaches the mocked workflow, unlike
     * {@link #createIssuance_InvalidDeliveryMode_Returns400()} below, which mocks a rejection that
     * happens one layer further in ({@code DeliveryMode.parse}, inside the workflow).
     */
    @Test
    void createIssuance_DeliveryContainsControlCharacters_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("direct\r\nX-Forged-Header: 1")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    /**
     * TDG-16: {@code email} only had {@code @NotBlank} before this fix -- a syntactically invalid
     * address reached the delivery workflow unrejected. Now bound by Bean Validation before the
     * workflow ever runs, same pattern as {@link #createIssuance_DeliveryContainsControlCharacters_Returns400WithoutInvokingWorkflow()}.
     */
    @Test
    void createIssuance_MalformedEmail_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("not-an-email")
                .delivery("email")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    @Test
    void createIssuance_CredentialConfigurationIdContainsControlCharacters_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema\r\nX-Forged-Header: 1")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("email")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    @Test
    void createIssuance_GrantTypeContainsControlCharacters_Returns400WithoutInvokingWorkflow() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("email")
                .grantType("authorization_code\r\nX-Forged-Header: 1")
                .build();

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();

        org.mockito.Mockito.verifyNoInteractions(issuanceWorkflow);
    }

    @Test
    void createIssuance_InvalidDeliveryMode_Returns400() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String detail = "Unknown delivery mode: foo";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), any()))
                .thenReturn(Mono.error(new InvalidDeliveryModeException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("invalid_request"), eq("Invalid request"),
                eq(HttpStatus.BAD_REQUEST), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "invalid_request", "Invalid request", HttpStatus.BAD_REQUEST.value(), detail,
                        UUID.randomUUID().toString())));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("invalid_request");
    }

    @Test
    void createIssuance_ModeNotEligible_Returns409() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String detail = "Delivery mode 'direct' is not eligible for credential type: test-schema";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), any()))
                .thenReturn(Mono.error(new DeliveryModeNotEligibleException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("delivery_mode_not_eligible"),
                eq("Delivery mode not eligible"), eq(HttpStatus.CONFLICT), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "delivery_mode_not_eligible", "Delivery mode not eligible", HttpStatus.CONFLICT.value(),
                        detail, UUID.randomUUID().toString())));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectBody()
                .jsonPath("$.type").isEqualTo("delivery_mode_not_eligible");
    }

    @Test
    void createIssuance_WhenSignedCredentialAndCredentialOfferUriAreAbsent_Returns202AcceptedWithoutBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }


    @Test
    void getAllIssuances_ReturnsIssuanceList() {
        String orgId = "testOrganizationId";
        AuthorizationDecision authCtx = organizationAdminDecision(orgId);

        IssuanceSummary summary = IssuanceSummary.builder()
                .issuanceId(UUID.randomUUID())
                .subject("testFullName")
                .status("testStatus")
                .createdAt(Instant.parse("2026-01-05T10:15:30.123Z"))
                .expiresAt(Instant.parse("2027-01-05T10:15:30Z"))
                .updated(Instant.now())
                .organizationIdentifier(orgId)
                .build();

        IssuanceList issuanceList = IssuanceList.builder()
                .issuances(List.of(new IssuanceList.IssuanceEntry(summary)))
                .build();

        when(powerAuthorizationService.authorize(eq(PowerAuthorizationService.QUERY), any(), any()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getAllIssuancesVisibleFor(authCtx))
                .thenReturn(Mono.just(issuanceList));

        webTestClient
                .get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_procedures").isArray()
                .jsonPath("$.credential_procedures[0].credential_procedure.created_at").isEqualTo("2026-01-05T10:15:30Z")
                .jsonPath("$.credential_procedures[0].credential_procedure.expires_at").isEqualTo("2027-01-05T10:15:30Z");
    }

    @Test
    void getAllIssuances_OmitsExpiresAtWhenThereIsNoExpiry() {
        String orgId = "testOrganizationId";
        AuthorizationDecision authCtx = organizationAdminDecision(orgId);

        IssuanceSummary summary = IssuanceSummary.builder()
                .issuanceId(UUID.randomUUID())
                .status("DRAFT")
                .createdAt(Instant.parse("2026-01-05T10:15:30Z"))
                .updated(Instant.now())
                .organizationIdentifier(orgId)
                .build();

        when(powerAuthorizationService.authorize(eq(PowerAuthorizationService.QUERY), any(), any()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getAllIssuancesVisibleFor(authCtx))
                .thenReturn(Mono.just(IssuanceList.builder()
                        .issuances(List.of(new IssuanceList.IssuanceEntry(summary)))
                        .build()));

        webTestClient
                .get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_procedures[0].credential_procedure.created_at").isEqualTo("2026-01-05T10:15:30Z")
                .jsonPath("$.credential_procedures[0].credential_procedure.expires_at").doesNotExist();
    }

    @Test
    void IssuanceController_getIssuance_decidesWithTheOrganizationStoredWithTheAttestation() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        AuthorizationDecision authCtx = organizationAdminDecision("VATES-STORED");
        CredentialDetails details = CredentialDetails.builder()
                .issuanceId(UUID.randomUUID())
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .lifeCycleStatus("VALID")
                .credential(null)
                .build();
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.just(storedIn("VATES-STORED")));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.QUERY, "VATES-STORED", issuanceId))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(authCtx, issuanceId))
                .thenReturn(Mono.just(details));

        // When / Then
        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.lifeCycleStatus").isEqualTo("VALID");
    }

    /** An id that is not in the tenant is decided without a resource (the platform administrator's cross-tenant view). */
    @Test
    void IssuanceController_getIssuance_decidesWithoutResourceWhenTheTenantHasNoSuchAttestation() {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        AuthorizationDecision authCtx = organizationAdminDecision("org");
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.empty());
        when(powerAuthorizationService.authorize(PowerAuthorizationService.QUERY, null, issuanceId))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(authCtx, issuanceId))
                .thenReturn(Mono.just(CredentialDetails.builder().lifeCycleStatus("VALID").build()));

        // When / Then
        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void IssuanceController_updateIssuanceStatus_withdrawIsDecidedOnTheStoredOrganization() throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.just(storedIn("VATES-STORED")));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.WITHDRAW, "VATES-STORED", issuanceId))
                .thenReturn(Mono.just(organizationAdminDecision("VATES-STORED")));
        when(issuanceService.withdrawIssuance(issuanceId)).thenReturn(Mono.empty());

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.WITHDRAWN).expectStatus().isNoContent();
        verify(issuanceService).withdrawIssuance(issuanceId);
    }

    @Test
    void IssuanceController_updateIssuanceStatus_archiveIsDecidedOnTheStoredOrganization() throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.just(storedIn("VATES-STORED")));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.ARCHIVE, "VATES-STORED", issuanceId))
                .thenReturn(Mono.just(organizationAdminDecision("VATES-STORED")));
        when(issuanceService.archiveIssuance(issuanceId)).thenReturn(Mono.empty());

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.ARCHIVED).expectStatus().isNoContent();
        verify(issuanceService).archiveIssuance(issuanceId);
    }

    /** A process stored before EUD-272, without organization, is decided as "" -- never as "no resource". */
    @Test
    void IssuanceController_updateIssuanceStatus_processWithoutOrganizationIsDecidedAsBelongingToNone()
            throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.just(storedIn(null)));
        when(powerAuthorizationService.authorize(PowerAuthorizationService.WITHDRAW, "", issuanceId))
                .thenReturn(Mono.error(new IssuanceNotFoundException("out of scope")));

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.WITHDRAWN)
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(204));
        verify(issuanceService, never()).withdrawIssuance(any());
    }

    /** W3 / AC-07: a user without powers can neither withdraw nor archive. */
    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = {"WITHDRAWN", "ARCHIVED"})
    void IssuanceController_updateIssuanceStatus_deniedDecisionNeverChangesTheProcess(CredentialStatusEnum target)
            throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.just(storedIn("VATES-STORED")));
        when(powerAuthorizationService.authorize(anyString(), eq("VATES-STORED"), eq(issuanceId)))
                .thenReturn(Mono.error(new LearIssuancePolicyException(
                        LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "no power")));

        // When / Then
        patchStatus(issuanceId, target).expectStatus().value(status -> assertThat(status).isNotEqualTo(204));
        verify(issuanceService, never()).withdrawIssuance(any());
        verify(issuanceService, never()).archiveIssuance(any());
    }

    /** A caller who may not withdraw at all is denied before learning whether the id exists. */
    @Test
    void IssuanceController_updateIssuanceStatus_missingProcessIsDecidedBeforeItIsNotFound() throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.empty());
        when(powerAuthorizationService.authorize(PowerAuthorizationService.WITHDRAW, null, issuanceId))
                .thenReturn(Mono.just(organizationAdminDecision("org")));

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.WITHDRAWN)
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(204));
        verify(powerAuthorizationService).authorize(PowerAuthorizationService.WITHDRAW, null, issuanceId);
        verify(issuanceService, never()).withdrawIssuance(any());
    }

    /** B1: revocation goes to the decision point (RevocationWorkflow → R1), with no read-only pre-check here. */
    @Test
    void IssuanceController_updateIssuanceStatus_revokeIsDecidedByTheRevocationWorkflow() throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(revocationWorkflow.revoke(anyString(), eq("Bearer testToken"), eq(issuanceId), isNull(), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.empty());

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.REVOKED).expectStatus().isNoContent();
        verifyNoInteractions(powerAuthorizationService);
    }

    @Test
    void IssuanceController_updateIssuanceStatus_unsupportedStatusReturns400() throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.VALID).expectStatus().isBadRequest();
    }

    private WebTestClient.ResponseSpec patchStatus(String issuanceId, CredentialStatusEnum target) throws JsonProcessingException {
        return webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(new UpdateIssuanceStatusRequest(target)))
                .exchange();
    }

    private static Issuance storedIn(String organization) {
        return Issuance.builder().issuanceId(UUID.randomUUID()).organizationIdentifier(organization).build();
    }

    private IssuanceRequest buildIssuanceRequest() {
        return IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();
    }

    private static AuthorizationDecision organizationAdminDecision(String orgId) {
        Caller caller = new Caller(orgId, List.of(), "sandbox", "learcredential.machine.w3c.3", "jti");
        RecognizedCaller recognized = new RecognizedCaller(caller, "sandbox", RecognizedCaller.ORGANIZATION_ADMIN,
                RecognizedCaller.ORGANIZATION_ADMIN, false, false);
        return new AuthorizationDecision(PowerAuthorizationService.QUERY, recognized, AuthorizationMatrix.Scope.OWN_ORGANIZATION);
    }

    /** The 403 mapping of the denial is SharedExceptionHandler's (SharedExceptionHandlerTest), not part of this slice. */
    @Test
    void getAllIssuances_DeniedByAuthorization_NeverQueries() {
        when(powerAuthorizationService.authorize(eq(PowerAuthorizationService.QUERY), any(), any()))
                .thenReturn(Mono.error(new LearIssuancePolicyException(
                        LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "no power")));

        webTestClient
                .get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().value(status -> org.assertj.core.api.Assertions.assertThat(status).isNotEqualTo(200));

        org.mockito.Mockito.verifyNoInteractions(issuanceService);
    }
}
