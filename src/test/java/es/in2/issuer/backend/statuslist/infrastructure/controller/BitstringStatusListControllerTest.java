package es.in2.issuer.backend.statuslist.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.statuslist.application.RevocationWorkflow;
import es.in2.issuer.backend.statuslist.application.StatusListWorkflow;
import es.in2.issuer.backend.statuslist.domain.model.dto.RevokeCredentialRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class BitstringStatusListControllerUnitTest {

    private static final String PUBLIC_BASE_URL = "https://test.example/issuer";

    private StatusListWorkflow statusListWorkflow;
    private RevocationWorkflow revocationWorkflow;
    private UrlResolver urlResolver;
    private BitstringStatusListController controller;

    @BeforeEach
    void setUp() {
        statusListWorkflow = mock(StatusListWorkflow.class);
        revocationWorkflow = mock(RevocationWorkflow.class);
        urlResolver = mock(UrlResolver.class);
        controller = new BitstringStatusListController(statusListWorkflow, revocationWorkflow, urlResolver);
    }

    private static ServerWebExchange newExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.post("/credentials/status/revoke"));
    }

    @Test
    void getStatusList_whenOk_returnsResponseEntityWithVcJwt() {
        long listId = 123L;
        String jwt = "header.payload.signature";

        when(statusListWorkflow.getSignedStatusListCredential(listId)).thenReturn(Mono.just(jwt));

        Mono<ResponseEntity<String>> result = controller.getStatusList(listId);

        StepVerifier.create(result)
                .assertNext(res -> {
                    assertThat(res.getStatusCode().value()).isEqualTo(200);
                    assertThat(res.getHeaders().getContentType()).isEqualTo(MediaType.parseMediaType("application/vc+jwt"));
                    assertThat(res.getBody()).isEqualTo(jwt);
                })
                .verifyComplete();

        verify(statusListWorkflow).getSignedStatusListCredential(listId);
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void getStatusList_whenWorkflowFails_propagatesError() {
        long listId = 123L;

        when(statusListWorkflow.getSignedStatusListCredential(listId))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(controller.getStatusList(listId))
                .expectError(RuntimeException.class)
                .verify();

        verify(statusListWorkflow).getSignedStatusListCredential(listId);
        verifyNoInteractions(revocationWorkflow);
    }

    @Test
    void revokeCredential_whenOk_completesAndInvokesWorkflow() {
        String bearerToken = "Bearer test-token";
        String issuanceId = UUID.randomUUID().toString();
        ServerWebExchange exchange = newExchange();

        RevokeCredentialRequest request = new RevokeCredentialRequest(issuanceId);

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(revocationWorkflow.revoke(anyString(), eq(bearerToken), eq(issuanceId), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.revokeCredential(bearerToken, request, exchange))
                .verifyComplete();

        verify(revocationWorkflow).revoke(anyString(), eq(bearerToken), eq(issuanceId), eq(PUBLIC_BASE_URL));
        verifyNoInteractions(statusListWorkflow);
    }

    @Test
    void revokeCredential_whenWorkflowFails_propagatesError() {
        String bearerToken = "Bearer test-token";
        String issuanceId = UUID.randomUUID().toString();
        ServerWebExchange exchange = newExchange();

        RevokeCredentialRequest request = new RevokeCredentialRequest(issuanceId);

        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(revocationWorkflow.revoke(anyString(), eq(bearerToken), eq(issuanceId), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.error(new RuntimeException("boom")));

        StepVerifier.create(controller.revokeCredential(bearerToken, request, exchange))
                .expectError(RuntimeException.class)
                .verify();

        verify(revocationWorkflow).revoke(anyString(), eq(bearerToken), eq(issuanceId), eq(PUBLIC_BASE_URL));
        verifyNoInteractions(statusListWorkflow);
    }
}
