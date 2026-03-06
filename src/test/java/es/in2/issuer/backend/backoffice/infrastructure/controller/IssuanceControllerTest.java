package es.in2.issuer.backend.backoffice.infrastructure.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.application.workflow.IssuanceWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.IssuanceResponse;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.infrastructure.config.IssuanceMetrics;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

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

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private IssuanceWorkflow issuanceWorkflow;

    @MockBean
    private IssuanceMetrics issuanceMetrics;

    @Test
    void issueCredential_UiDelivery_Returns200WithBody() throws JsonProcessingException {

        String credentialOfferUri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fserver.example.com%2Fcredential-offer%2Fabc123";
        var testRequest = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();

        when(issuanceWorkflow.execute(anyString(), eq(testRequest), isNull()))
                .thenReturn(Mono.just(IssuanceResponse.builder().credentialOfferUri(credentialOfferUri).build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri("/v1/issuances")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.credential_offer_uri").isEqualTo(credentialOfferUri);
    }

    @Test
    void issueCredential_Deferred_Returns202Accepted() throws JsonProcessingException {

        var testRequest = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();

        when(issuanceWorkflow.execute(anyString(), eq(testRequest), isNull()))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri("/v1/issuances")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }

    @Test
    void issueCredential_WithIdToken_PassesIdTokenToWorkflow() throws JsonProcessingException {

        String idToken = "id-token-value";
        var testRequest = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("test-schema")
                .payload(objectMapper.createObjectNode().put("key", "value"))
                .email("test@example.com")
                .build();

        when(issuanceWorkflow.execute(anyString(), eq(testRequest), eq(idToken)))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        webTestClient.mutateWith(csrf())
                .post()
                .uri("/v1/issuances")
                .header("X-Id-Token", idToken)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(objectMapper.writeValueAsString(testRequest))
                .exchange()
                .expectStatus().isAccepted()
                .expectBody().isEmpty();
    }
}
