package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.issuance.domain.model.dtos.UpdateIssuanceStatusRequest;
import es.in2.issuer.backend.issuance.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.oidc4vci.domain.service.NonceService;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@MockBean(ReactiveAuthenticationManager.class)
@WebFluxTest(IssuanceController.class)
class IssuanceControllerTest {

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    ErrorResponseFactory errorResponseFactory;

    @MockBean
    private NonceService nonceService;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private IssuanceWorkflow issuanceWorkflow;

    @MockBean
    private IssuanceService issuanceService;

    @MockBean
    private AccessTokenService accessTokenService;

    @MockBean
    private RevocationWorkflow revocationWorkflow;

    @MockBean
    private IssuanceMetrics issuanceMetrics;

    @Test
    void createIssuance_UiDelivery_Returns200WithBody() throws JsonProcessingException {
        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2Fabc123";
        var testRequest = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();

        when(issuanceWorkflow.issueCredential(anyString(), eq(testRequest), isNull()))
                .thenReturn(Mono.just(IssuanceResponse.builder().credentialOfferUri(credentialOfferUri).build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri("/api/v1/issuances")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_offer_uri").isEqualTo(credentialOfferUri);
    }

    @Test
    void createIssuance_Deferred_Returns202Accepted() throws JsonProcessingException {
        var testRequest = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();

        when(issuanceWorkflow.issueCredential(anyString(), eq(testRequest), isNull()))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri("/api/v1/issuances")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void createIssuance_WithIdToken_PassesIdTokenToWorkflow() throws JsonProcessingException {
        String idToken = "id-token-value";
        var testRequest = IssuanceRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();

        when(issuanceWorkflow.issueCredential(anyString(), eq(testRequest), eq(idToken)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri("/api/v1/issuances")
                .header("X-Id-Token", idToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void getAllIssuances_ReturnsIssuanceList() {
        String orgId = "testOrganizationId";
        OrgContext orgContext = new OrgContext(orgId, false);

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

        when(accessTokenService.getOrganizationContext(anyString()))
                .thenReturn(Mono.just(orgContext));
        when(issuanceService.getAllIssuancesVisibleFor(orgId, false))
                .thenReturn(Mono.just(issuanceList));

        webTestClient
                .get()
                .uri("/api/v1/issuances")
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
        OrgContext orgContext = new OrgContext(orgId, false);

        CredentialDetails details = CredentialDetails.builder()
                .issuanceId(UUID.randomUUID())
                .credentialConfigurationId("learcredential.employee.w3c.4")
                .lifeCycleStatus("VALID")
                .credential(null)
                .build();

        when(accessTokenService.getOrganizationContext(anyString()))
                .thenReturn(Mono.just(orgContext));
        when(issuanceService.getIssuanceDetailByIssuanceIdAndOrganizationId(orgId, issuanceId, false))
                .thenReturn(Mono.just(details));

        webTestClient
                .get()
                .uri("/api/v1/issuances/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.lifeCycleStatus").isEqualTo("VALID");
    }

    @Test
    void updateIssuanceStatus_Withdrawn_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        var request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.WITHDRAWN);

        when(issuanceService.withdrawIssuance(issuanceId))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri("/api/v1/issuances/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_Revoked_Returns204() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        var request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.REVOKED);

        when(revocationWorkflow.revoke(anyString(), eq("Bearer testToken"), eq(issuanceId)))
                .thenReturn(Mono.empty());

        webTestClient.mutateWith(csrf())
                .patch()
                .uri("/api/v1/issuances/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    void updateIssuanceStatus_UnsupportedStatus_Returns400() throws JsonProcessingException {
        String issuanceId = UUID.randomUUID().toString();
        var request = new UpdateIssuanceStatusRequest(CredentialStatusEnum.VALID);

        webTestClient.mutateWith(csrf())
                .patch()
                .uri("/api/v1/issuances/{id}", issuanceId)
                .header("Authorization", "Bearer testToken")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(request))
                .exchange()
                .expectStatus().isBadRequest();
    }
}
