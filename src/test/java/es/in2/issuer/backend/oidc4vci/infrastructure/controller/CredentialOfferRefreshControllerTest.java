package es.in2.issuer.backend.oidc4vci.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.CredentialOfferRefreshWorkflow;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.result.view.Rendering;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferRefreshControllerTest {

    private static final String PUBLIC_BASE_URL = "https://test.example/issuer";

    @Mock
    private CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;

    @Mock
    private UrlResolver urlResolver;

    @InjectMocks
    private CredentialOfferRefreshController controller;

    private static ServerWebExchange newExchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/credential-offer/refresh/x"));
    }

    @Test
    void shouldReturnSuccessViewOnRefresh() {
        String credentialOfferRefreshToken = "valid-token";
        ServerWebExchange exchange = newExchange();
        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(credentialOfferRefreshWorkflow.refreshCredentialOffer(eq(credentialOfferRefreshToken), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.refreshCredentialOffer(credentialOfferRefreshToken, exchange))
                .assertNext(rendering -> assertEquals("credential-offer-refresh-success", extractViewName(rendering)))
                .verifyComplete();
    }

    @Test
    void shouldReturnErrorViewOnFailure() {
        String credentialOfferRefreshToken = "invalid-token";
        ServerWebExchange exchange = newExchange();
        when(urlResolver.publicIssuerBaseUrl(any(ServerWebExchange.class))).thenReturn(PUBLIC_BASE_URL);
        when(credentialOfferRefreshWorkflow.refreshCredentialOffer(eq(credentialOfferRefreshToken), eq(PUBLIC_BASE_URL)))
                .thenReturn(Mono.error(new RuntimeException("Token not found")));

        StepVerifier.create(controller.refreshCredentialOffer(credentialOfferRefreshToken, exchange))
                .assertNext(rendering -> assertEquals("credential-offer-refresh-error", extractViewName(rendering)))
                .verifyComplete();
    }

    private String extractViewName(Rendering rendering) {
        return rendering.view() instanceof String viewName ? viewName : rendering.view().toString();
    }
}
