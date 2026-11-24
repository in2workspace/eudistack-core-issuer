package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.application.workflow.CredentialOfferRenewalWorkflow;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.exception.OfferNotRenewableException;
import es.in2.issuer.backend.issuance.domain.exception.RenewalDeliveryFailedException;
import es.in2.issuer.backend.issuance.domain.model.CredentialOfferRenewal;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.exception.DeliveryModeNotEligibleException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidDeliveryModeException;
import es.in2.issuer.backend.issuance.domain.exception.InvalidGrantTypeException;
import es.in2.issuer.backend.issuance.domain.model.DeliveryResult;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceDetail;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.MalformedIssuanceIdException;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.exception.AuditTrailUnavailableException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.IssuanceQueryUnavailableException;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.service.IssuanceQueryService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.mockito.ArgumentCaptor;
import es.in2.issuer.backend.shared.infrastructure.config.tenantconfig.TenantCustomDomainsLoader;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.server.ResponseStatusException;
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

    @MockitoBean
    private IssuanceQueryService issuanceQueryService;

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

    @MockitoBean
    private CredentialOfferRenewalWorkflow credentialOfferRenewalWorkflow;

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

    /**
     * EUD-268 (EUD-254 §5): a product certification is requested like any other type. An X-Id-Token
     * header is neither required nor read by the issuance: the request reaches the workflow unchanged.
     */
    @Test
    void createIssuance_ProductCertificationWithAnXIdTokenHeader_IgnoresIt() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("gx.labelcredential.w3c.2")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("email")
                .build();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .deliveryResults(List.of(DeliveryResult.dispatched("email")))
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .header("X-Id-Token", "not.even.a-jwt")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.responses[0].channel").isEqualTo("email");

        verify(issuanceWorkflow).issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL));
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

    /**
     * EUD-268: a delivery other than exactly one of its three values -- control characters included -- is
     * the contract's invalid_delivery_mode, decided by the workflow, not a BAD_REQUEST on its shape. The
     * value is never logged, tagged nor echoed back (IssuanceWorkflowImplTest).
     */
    @Test
    void createIssuance_DeliveryNotOneOfItsValues_Returns400InvalidDeliveryMode() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("direct\r\nX-Forged-Header: 1")
                .build();
        String detail = "delivery must be one of: email, ui, direct";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), any()))
                .thenReturn(Mono.error(new InvalidDeliveryModeException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("invalid_delivery_mode"), eq("Invalid delivery mode"),
                eq(HttpStatus.BAD_REQUEST), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "invalid_delivery_mode", "Invalid delivery mode", HttpStatus.BAD_REQUEST.value(), detail,
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
                .jsonPath("$.type").isEqualTo("invalid_delivery_mode")
                .jsonPath("$.detail").isEqualTo(detail);
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

    /**
     * EUD-268: a grant_type other than its two values -- control characters included -- is the
     * contract's invalid_grant_type, decided by the workflow (OfferGrantType), not a BAD_REQUEST on its
     * shape. The value is never logged nor echoed back (OfferGrantTypeTest).
     */
    @Test
    void createIssuance_GrantTypeNotOneOfItsValues_Returns400InvalidGrantType() throws JsonProcessingException {
        IssuanceRequest request = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .delivery("email")
                .grantType("authorization_code\r\nX-Forged-Header: 1")
                .build();
        String detail = "grant_type must be one of: authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), any()))
                .thenReturn(Mono.error(new InvalidGrantTypeException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("invalid_grant_type"), eq("Invalid grant type"),
                eq(HttpStatus.BAD_REQUEST), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "invalid_grant_type", "Invalid grant type", HttpStatus.BAD_REQUEST.value(), detail,
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
                .jsonPath("$.type").isEqualTo("invalid_grant_type")
                .jsonPath("$.detail").isEqualTo(detail);
    }

    @Test
    void createIssuance_InvalidDeliveryMode_Returns400() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String detail = "delivery must be one of: email, ui, direct";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), any()))
                .thenReturn(Mono.error(new InvalidDeliveryModeException(detail)));
        when(errorResponseFactory.handleWith(any(), any(), eq("invalid_delivery_mode"), eq("Invalid delivery mode"),
                eq(HttpStatus.BAD_REQUEST), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "invalid_delivery_mode", "Invalid delivery mode", HttpStatus.BAD_REQUEST.value(), detail,
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
                .jsonPath("$.type").isEqualTo("invalid_delivery_mode");
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


    private static final String ISSUANCE_ID = "6f1c1c1e-5a0b-4d52-9d58-1f3b6f0d2a11";

    private WebTestClient.ResponseSpec postIssuance(IssuanceResponse workflowResponse) throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(workflowResponse));
        return webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange();
    }

    private static String expectedLocation(String id) {
        return PUBLIC_ISSUER_BASE_URL + ISSUANCES_PATH + "/" + id;
    }

    @Test
    void createIssuance_Email_ReturnsLocationOfTheCreatedProcess() throws JsonProcessingException {
        postIssuance(IssuanceResponse.builder()
                .credentialOfferUri("openid-credential-offer://x")
                .deliveryResults(List.of(DeliveryResult.dispatched("email")))
                .issuanceId(ISSUANCE_ID)
                .build())
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.LOCATION, expectedLocation(ISSUANCE_ID));
    }

    @Test
    void createIssuance_Ui_ReturnsLocationOfTheCreatedProcess() throws JsonProcessingException {
        postIssuance(IssuanceResponse.builder()
                .credentialOfferUri("openid-credential-offer://x")
                .deliveryResults(List.of(DeliveryResult.dispatched("ui")))
                .issuanceId(ISSUANCE_ID)
                .build())
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.LOCATION, expectedLocation(ISSUANCE_ID));
    }

    @Test
    void createIssuance_Direct_ReturnsLocationOfTheCreatedProcess() throws JsonProcessingException {
        postIssuance(IssuanceResponse.builder()
                .signedCredential("signed-jwt")
                .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                .issuanceId(ISSUANCE_ID)
                .build())
                .expectStatus().isOk()
                .expectHeader().valueEquals(HttpHeaders.LOCATION, expectedLocation(ISSUANCE_ID));
    }

    @Test
    void createIssuance_WorkflowError_ReturnsNoLocation() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(BEARER_TOKEN), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.CONFLICT)));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("Authorization", BEARER_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectHeader().doesNotExist(HttpHeaders.LOCATION);
    }

    @Test
    void createIssuance_BodyDoesNotSerializeTheProcessId() throws JsonProcessingException {
        postIssuance(IssuanceResponse.builder()
                .signedCredential("signed-jwt")
                .deliveryResults(List.of(DeliveryResult.delivered("direct")))
                .issuanceId(ISSUANCE_ID)
                .build())
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body).doesNotContain(ISSUANCE_ID));
    }

    /** EUD-255 FR-06: answered with the shape of the contract; the use case decides and traces (AD-7). */
    @Test
    void IssuanceController_getIssuance_answersTheShapeOfTheContract() {
        // Given
        UUID issuanceId = UUID.randomUUID();
        IssuanceDetail detail = new IssuanceDetail(IssuanceSummary.builder()
                .id(issuanceId)
                .organizationIdentifier("VATES-STORED")
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .lifeCycleStatus("VALID")
                .created(Instant.parse("2026-10-01T09:10:02Z"))
                .updated(Instant.parse("2026-10-01T09:12:44Z"))
                .build(), objectMapper.createObjectNode().put("given_name", "Ana"));
        when(issuanceQueryService.detail(issuanceId)).thenReturn(Mono.just(detail));

        // When / Then: the fields of the listing at the top level, plus the attestation data
        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo(issuanceId.toString())
                .jsonPath("$.life_cycle_status").isEqualTo("VALID")
                .jsonPath("$.credential_configuration_id").isEqualTo("learcredential.employee.w3c.4")
                .jsonPath("$.updated").isEqualTo("2026-10-01T09:12:44Z")
                .jsonPath("$.credential.given_name").isEqualTo("Ana")
                .jsonPath("$.summary").doesNotExist()
                .jsonPath("$.procedure_id").doesNotExist()
                .jsonPath("$.lifeCycleStatus").doesNotExist();
    }

    /** EUD-255 AD-7, AC-10: a read that could not be traced answers internal_error and nothing of the read. */
    @Test
    void IssuanceController_getIssuance_whoseTraceFails_isAnInternalErrorWithoutData() {
        // Given
        UUID issuanceId = UUID.randomUUID();
        delegateProblemsToTheRealFactory();
        when(issuanceQueryService.detail(issuanceId)).thenReturn(Mono.error(
                new AuditTrailUnavailableException(new IllegalStateException("outbox unavailable"))));

        // When / Then
        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isEqualTo(500)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("internal_error")
                .jsonPath("$.detail").isEqualTo("The request could not be completed")
                .jsonPath("$.id").doesNotExist()
                .jsonPath("$.credential").doesNotExist();
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
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.just(storedIn("VATES-STORED")));
        when(revocationWorkflow.revoke(anyString(), eq("Bearer testToken"), eq(issuanceId), isNull(), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.empty());

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.REVOKED).expectStatus().isNoContent();
        verifyNoInteractions(powerAuthorizationService);
    }

    /** Round 2 (N-2): a process that is not in the tenant is decided (and traced) before it is not found. */
    @ParameterizedTest
    @ValueSource(strings = {"00000000-0000-0000-0000-000000000000", "not-a-uuid"})
    void IssuanceController_updateIssuanceStatus_revokeOfAMissingProcessIsDecidedBeforeItIsNotFound(String issuanceId)
            throws JsonProcessingException {
        // Given: a malformed id is traced as a fixed marker, never as the string the client sent (L1)
        String tracedId = "not-a-uuid".equals(issuanceId) ? IssuanceController.MALFORMED_ID : issuanceId;
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceService.getIssuanceById(issuanceId)).thenReturn(Mono.empty());
        when(powerAuthorizationService.authorize(PowerAuthorizationService.REVOKE, null, tracedId))
                .thenReturn(Mono.just(organizationAdminDecision("org")));

        // When / Then: not found -- never a 500 for a malformed id -- and the workflow is not reached
        patchStatus(issuanceId, CredentialStatusEnum.REVOKED).expectStatus().value(status -> assertThat(status).isNotIn(204, 500));
        verify(powerAuthorizationService).authorize(PowerAuthorizationService.REVOKE, null, tracedId);
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void IssuanceController_updateIssuanceStatus_unsupportedStatusReturns400() throws JsonProcessingException {
        // Given
        String issuanceId = UUID.randomUUID().toString();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);

        // When / Then
        patchStatus(issuanceId, CredentialStatusEnum.VALID).expectStatus().isBadRequest();
    }

    /**
     * EUD-255 API-10: the shape goes before the permission. An id that is not a UUID -- a non-canonical one
     * ("1-1-1-1-1", accepted by UUID.fromString) too -- is an invalid request of the id, never decided, looked
     * up nor echoed.
     */
    @ParameterizedTest
    @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1"})
    @SuppressWarnings("unchecked")
    void IssuanceController_getIssuance_malformedIdIsAnInvalidRequest_beforeDecidingAnything(String malformed) {
        // Given
        ArgumentCaptor<List<GlobalErrorMessage.FieldViolation>> violations = ArgumentCaptor.forClass(List.class);
        when(errorResponseFactory.handleWithViolations(any(InvalidQueryException.class), any(), eq("invalid_request"),
                anyString(), eq(HttpStatus.BAD_REQUEST), anyString(), violations.capture()))
                .thenReturn(Mono.just(new GlobalErrorMessage("invalid_request", "Invalid request",
                        HttpStatus.BAD_REQUEST.value(), "The query is not valid", ISSUANCES_PATH)));

        // When / Then
        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", malformed)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("invalid_request");
        assertThat(violations.getValue()).extracting(GlobalErrorMessage.FieldViolation::field).containsExactly("id");
        assertThat(violations.getValue().toString()).doesNotContain(malformed);
        verifyNoInteractions(powerAuthorizationService, issuanceQueryService);
        verify(issuanceService, never()).getIssuanceById(anyString());
    }

    /** EUD-307: revoking, withdrawing or archiving an id that is not a UUID is decided, then rejected as 400 BAD_REQUEST. */
    @ParameterizedTest
    @EnumSource(value = CredentialStatusEnum.class, names = {"REVOKED", "WITHDRAWN", "ARCHIVED"})
    void IssuanceController_updateIssuanceStatus_malformedIdIsDecidedThenRejectedAsBadRequest(CredentialStatusEnum target)
            throws JsonProcessingException {
        // Given
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(powerAuthorizationService.authorize(anyString(), isNull(), eq(IssuanceController.MALFORMED_ID)))
                .thenReturn(Mono.just(organizationAdminDecision("org")));
        stubBadRequestProblem();

        // When / Then
        patchStatus("not-a-uuid", target)
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST");
        verify(issuanceService, never()).getIssuanceById(anyString());
        verify(issuanceService, never()).withdrawIssuance(any());
        verify(issuanceService, never()).archiveIssuance(any());
        verifyNoInteractions(revocationWorkflow);
    }

    private void stubBadRequestProblem() {
        when(errorResponseFactory.handleWith(any(MalformedIssuanceIdException.class), any(), eq("BAD_REQUEST"),
                anyString(), eq(HttpStatus.BAD_REQUEST), anyString()))
                .thenReturn(Mono.just(new GlobalErrorMessage(
                        "BAD_REQUEST", "Bad Request", HttpStatus.BAD_REQUEST.value(),
                        "The issuance id is not a UUID", UUID.randomUUID().toString())));
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

    /** EUD-255 FR-03/FR-04: the filters reach the query use case already checked, and the page goes out as the contract says. */
    @Test
    void listIssuances_passesTheFiltersToTheQuery_andAnswersThePageOfTheContract() {
        AuthorizationDecision decision = organizationAdminDecision("VATES-LIST");
        UUID id = UUID.randomUUID();
        IssuanceList page = new IssuanceList(List.of(IssuanceSummary.builder()
                .id(id)
                .organizationIdentifier("VATES-LIST")
                .credentialConfigurationId("doctor.sd.1")
                .lifeCycleStatus("VALID")
                .created(Instant.parse("2026-10-01T09:10:02Z"))
                .updated(Instant.parse("2026-10-01T09:12:44Z"))
                .build()), null);
        ArgumentCaptor<IssuanceQuery> query = ArgumentCaptor.forClass(IssuanceQuery.class);
        when(powerAuthorizationService.authorizeQuery(isNull(), isNull())).thenReturn(Mono.just(decision));
        when(issuanceQueryService.list(eq(decision), query.capture())).thenReturn(Mono.just(page));

        webTestClient.get()
                .uri(ISSUANCES_PATH + "?life_cycle_status=VALID,REVOKED&credential_configuration_id=doctor.sd.1&limit=10")
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .contains("\"issuances\":[{\"id\":\"" + id + "\"")
                        .contains("\"life_cycle_status\":\"VALID\"")
                        .contains("\"updated\":\"2026-10-01T09:12:44Z\"")
                        .contains("\"next_cursor\":null"));

        assertThat(query.getValue().lifeCycleStatuses())
                .containsExactlyInAnyOrder(CredentialStatusEnum.VALID, CredentialStatusEnum.REVOKED);
        assertThat(query.getValue().credentialConfigurationId()).isEqualTo("doctor.sd.1");
        assertThat(query.getValue().limit()).isEqualTo(10);
        assertThat(query.getValue().cursor()).isNull();
    }

    /** API-10: the shape goes before the permission, and every field with a problem is reported. */
    @Test
    @SuppressWarnings("unchecked")
    void listIssuances_rejectsAMalformedQuery_beforeDecidingAnything() {
        ArgumentCaptor<List<GlobalErrorMessage.FieldViolation>> violations = ArgumentCaptor.forClass(List.class);
        when(errorResponseFactory.handleWithViolations(any(InvalidQueryException.class), any(), eq("invalid_request"),
                anyString(), eq(HttpStatus.BAD_REQUEST), anyString(), violations.capture()))
                .thenReturn(Mono.just(new GlobalErrorMessage("invalid_request", "Invalid request",
                        HttpStatus.BAD_REQUEST.value(), "The query is not valid", ISSUANCES_PATH)));

        webTestClient.get()
                .uri(ISSUANCES_PATH + "?life_cycle_status=VALID,ACTIVE&limit=500&cursor=not-a-cursor")
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isBadRequest();

        assertThat(violations.getValue()).extracting(GlobalErrorMessage.FieldViolation::field)
                .containsExactly("life_cycle_status", "limit", "cursor");
        verifyNoInteractions(powerAuthorizationService, issuanceQueryService);
    }

    /** EUD-255 AD-7, AC-10: a page that could not be traced answers internal_error and no process. */
    @Test
    void listIssuances_whoseTraceFails_isAnInternalErrorWithoutData() {
        AuthorizationDecision decision = organizationAdminDecision("VATES-LIST");
        delegateProblemsToTheRealFactory();
        when(powerAuthorizationService.authorizeQuery(isNull(), isNull())).thenReturn(Mono.just(decision));
        when(issuanceQueryService.list(eq(decision), any())).thenReturn(Mono.error(
                new AuditTrailUnavailableException(new IllegalStateException("outbox unavailable"))));

        webTestClient.get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isEqualTo(500)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("internal_error")
                .jsonPath("$.issuances").doesNotExist();
    }

    /** EUD-255 FR-11: the body reaches the query use case already checked, as a page of the listing with the text. */
    @Test
    void searchIssuances_passesTheSearchToTheQuery_andAnswersThePageOfTheContract() {
        AuthorizationDecision decision = organizationAdminDecision("VATES-LIST");
        ArgumentCaptor<IssuanceQuery> query = ArgumentCaptor.forClass(IssuanceQuery.class);
        when(powerAuthorizationService.authorizeQuery(isNull(), isNull())).thenReturn(Mono.just(decision));
        when(issuanceQueryService.list(eq(decision), query.capture()))
                .thenReturn(Mono.just(new IssuanceList(List.of(), null)));

        webTestClient.mutateWith(csrf()).post()
                .uri(ISSUANCES_PATH + "/search")
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"garcia\", \"life_cycle_status\": [\"VALID\"], \"limit\": 5}")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.issuances").isArray()
                .jsonPath("$.next_cursor").doesNotExist();

        assertThat(query.getValue().subject()).isEqualTo("garcia");
        assertThat(query.getValue().lifeCycleStatuses()).containsExactly(CredentialStatusEnum.VALID);
        assertThat(query.getValue().limit()).isEqualTo(5);
    }

    /** API-10, ES-04: the body is checked before the permission, and the search is not attempted. */
    @Test
    void searchIssuances_rejectsAMalformedBody_beforeDecidingAnything() {
        when(errorResponseFactory.handleWithViolations(any(InvalidQueryException.class), any(), eq("invalid_request"),
                anyString(), eq(HttpStatus.BAD_REQUEST), anyString(), any()))
                .thenReturn(Mono.just(new GlobalErrorMessage("invalid_request", "Invalid request",
                        HttpStatus.BAD_REQUEST.value(), "The query is not valid", ISSUANCES_PATH + "/search")));

        webTestClient.mutateWith(csrf()).post()
                .uri(ISSUANCES_PATH + "/search")
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"ma\"}")
                .exchange()
                .expectStatus().isBadRequest();

        verifyNoInteractions(powerAuthorizationService, issuanceQueryService);
    }

    /** EUD-255 AD-3, ES-01: a page whose processes could not be read answers internal_error and no process. */
    @Test
    void listIssuances_whoseProcessesCannotBeRead_isAnInternalErrorWithoutData() {
        AuthorizationDecision decision = organizationAdminDecision("VATES-LIST");
        delegateProblemsToTheRealFactory();
        when(powerAuthorizationService.authorizeQuery(isNull(), isNull())).thenReturn(Mono.just(decision));
        when(issuanceQueryService.list(eq(decision), any())).thenReturn(Mono.error(
                new IssuanceQueryUnavailableException(new IllegalStateException("schema down"))));

        webTestClient.get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isEqualTo(500)
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("internal_error")
                .jsonPath("$.detail").isEqualTo("The request could not be completed")
                .jsonPath("$.issuances").doesNotExist();
    }

    /** The 403 mapping of the denial is SharedExceptionHandler's (SharedExceptionHandlerTest), not part of this slice. */
    @Test
    void listIssuances_deniedByAuthorization_neverQueries() {
        when(powerAuthorizationService.authorizeQuery(any(), any()))
                .thenReturn(Mono.error(new LearIssuancePolicyException(
                        LearIssuancePolicyException.Reason.OPERATOR_LACKS_ONBOARDING, "no power")));

        webTestClient.get()
                .uri(ISSUANCES_PATH)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().value(status -> assertThat(status).isNotEqualTo(200));

        verifyNoInteractions(issuanceQueryService);
    }

    private static AuthorizationDecision organizationAdminDecision(String orgId) {
        Caller caller = new Caller(orgId, List.of(), "sandbox", "learcredential.machine.w3c.3", "jti");
        RecognizedCaller recognized = new RecognizedCaller(caller, "sandbox", RecognizedCaller.ORGANIZATION_ADMIN,
                RecognizedCaller.ORGANIZATION_ADMIN, false, false);
        return new AuthorizationDecision(PowerAuthorizationService.QUERY, recognized, AuthorizationMatrix.Scope.OWN_ORGANIZATION);
    }

    // ── POST /api/v1/issuances/{id}/credential-offer (EUD-295) ──────────────────────────────

    private static final String RENEWAL_ID = "0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90";
    private static final String RENEWAL_PATH = ISSUANCES_PATH + "/" + RENEWAL_ID + "/credential-offer";

    @Test
    void renewCredentialOffer_ui_returns200WithTheNewOfferUri() {
        String uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fnew";
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(credentialOfferRenewalWorkflow.renewCredentialOffer(RENEWAL_ID, PUBLIC_ISSUER_BASE_URL))
                .thenReturn(Mono.just(new CredentialOfferRenewal(DeliveryMode.UI, uri)));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(RENEWAL_PATH)
                .header("Authorization", BEARER_TOKEN)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody()
                .jsonPath("$.responses.length()").isEqualTo(1)
                .jsonPath("$.responses[0].channel").isEqualTo("ui")
                .jsonPath("$.responses[0].status").isEqualTo(200)
                .jsonPath("$.responses[0].body.credential_offer_uri").isEqualTo(uri);
    }

    @Test
    void renewCredentialOffer_email_returns200WithoutBody() {
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(credentialOfferRenewalWorkflow.renewCredentialOffer(RENEWAL_ID, PUBLIC_ISSUER_BASE_URL))
                .thenReturn(Mono.just(new CredentialOfferRenewal(DeliveryMode.EMAIL, null)));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(RENEWAL_PATH)
                .header("Authorization", BEARER_TOKEN)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .json("{\"responses\":[{\"channel\":\"email\",\"status\":200}]}", true);
    }

    @Test
    void renewCredentialOffer_notRenewable_returns409ProblemJson() {
        delegateProblemsToTheRealFactory();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(credentialOfferRenewalWorkflow.renewCredentialOffer(anyString(), anyString()))
                .thenReturn(Mono.error(new OfferNotRenewableException("REVOKED")));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(RENEWAL_PATH)
                .header("Authorization", BEARER_TOKEN)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("offer_not_renewable")
                .jsonPath("$.status").isEqualTo(409);
    }

    @Test
    void renewCredentialOffer_deliveryFailed_returns503ProblemJsonWithRetryAfter() {
        delegateProblemsToTheRealFactory();
        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(credentialOfferRenewalWorkflow.renewCredentialOffer(anyString(), anyString()))
                .thenReturn(Mono.error(new RenewalDeliveryFailedException("smtp")));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(RENEWAL_PATH)
                .header("Authorization", BEARER_TOKEN)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.SERVICE_UNAVAILABLE)
                .expectHeader().contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .expectHeader().exists("Retry-After")
                .expectBody()
                .jsonPath("$.type").isEqualTo("wallet_delivery_timeout");
    }

    /** ErrorResponseFactory is a mock in this slice; the renewal problems need its real headers. */
    private void delegateProblemsToTheRealFactory() {
        ErrorResponseFactory real = new ErrorResponseFactory();
        when(errorResponseFactory.problem(any(), any(), anyString(), anyString(), any(), anyString(), any()))
                .thenAnswer(inv -> real.problem(inv.getArgument(0), inv.getArgument(1), inv.getArgument(2),
                        inv.getArgument(3), inv.getArgument(4), inv.getArgument(5), inv.getArgument(6)));
    }
}
