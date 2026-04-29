package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.domain.model.dto.AuthorizationContext;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialDetails;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceList;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceSummary;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
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
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockitoBean(types = ReactiveAuthenticationManager.class)
@WebFluxTest(IssuanceController.class)
class IssuanceControllerTest {

    private static final String ISSUANCES_PATH = "/api/v1/issuances";
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
    private AccessTokenService accessTokenService;

    @MockitoBean
    private RevocationWorkflow revocationWorkflow;

    @MockitoBean
    private IssuanceMetrics issuanceMetrics;

    @MockitoBean
    private TenantRegistryService tenantRegistryService;

    @MockitoBean
    private UrlResolver urlResolver;;

    @Test
    void createIssuance_WhenCredentialOfferUriIsPresent_Returns200WithBody() throws JsonProcessingException {
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2Fabc123";
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .credentialOfferUri(credentialOfferUri)
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_offer_uri").isEqualTo(credentialOfferUri);
    }

    @Test
    void createIssuance_WhenSignedCredentialIsPresent_Returns200WithBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();
        String signedCredential = "signed-credential-value";

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder()
                        .signedCredential(signedCredential)
                        .build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.signed_credential").isEqualTo(signedCredential);
    }

    @Test
    void createIssuance_WhenSignedCredentialAndCredentialOfferUriAreAbsent_Returns202AcceptedWithoutBody() throws JsonProcessingException {
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), isNull(), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void createIssuance_WithIdToken_PassesIdTokenToWorkflow() throws JsonProcessingException {
        String idToken = "id-token-value";
        IssuanceRequest request = buildIssuanceRequest();

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(issuanceWorkflow.issueCredential(anyString(), eq(request), eq(idToken), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri(ISSUANCES_PATH)
                .header("X-Id-Token", idToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void getAllIssuances_ReturnsIssuanceList() {
        String orgId = "testOrganizationId";
        AuthorizationContext authCtx = new AuthorizationContext(orgId, UserRole.LEAR, false);

        IssuanceSummary summary = IssuanceSummary.builder()
                .issuanceId(UUID.randomUUID())
                .subject("testFullName")
                .status("testStatus")
                .updated(Instant.now())
                .organizationIdentifier(orgId)
                .build();

        IssuanceList issuanceList = IssuanceList.builder()
                .issuances(List.of(new IssuanceList.IssuanceEntry(summary)))
                .build();

        when(accessTokenService.getAuthorizationContext(anyString()))
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
                .jsonPath("$.credential_procedures").isArray();
    }

    @Test
    void getIssuance_ReturnsCredentialDetails() {
        String orgId = "testOrganizationId";
        String issuanceId = "test-issuance-id";
        AuthorizationContext authCtx = new AuthorizationContext(orgId, UserRole.LEAR, false);

        CredentialDetails details = CredentialDetails.builder()
                .issuanceId(UUID.randomUUID())
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .lifeCycleStatus("VALID")
                .credential(null)
                .build();

        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(authCtx, issuanceId))
                .thenReturn(Mono.just(details));

        webTestClient
                .get()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.lifeCycleStatus").isEqualTo("VALID");
    }

    @Test
    void updateIssuanceStatus_WithdrawnByTenantAdmin_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.WITHDRAWN);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false);

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.withdrawIssuance(issuanceId))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_ArchivedByTenantAdmin_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.ARCHIVED);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false);

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(issuanceService.archiveIssuance(issuanceId))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_Revoked_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.REVOKED);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false);

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));
        when(revocationWorkflow.revoke(anyString(), eq("Bearer testToken"), eq(issuanceId), eq(PUBLIC_ISSUER_BASE_URL)))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_UnsupportedStatus_Returns400() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.VALID);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.TENANT_ADMIN, false);

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void updateIssuanceStatus_WhenReadOnlyContext_Returns403() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        UpdateIssuanceStatusRequest request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.WITHDRAWN);
        AuthorizationContext authCtx = new AuthorizationContext("testOrg", UserRole.LEAR, true);

        when(urlResolver.publicIssuerBaseUrl(any())).thenReturn(PUBLIC_ISSUER_BASE_URL);
        when(accessTokenService.getAuthorizationContext(anyString()))
                .thenReturn(Mono.just(authCtx));

        webTestClient.mutateWith(csrf())
                .patch()
                .uri(ISSUANCES_PATH + "/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isForbidden();
    }

    private IssuanceRequest buildIssuanceRequest() {
        return IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();
    }
}