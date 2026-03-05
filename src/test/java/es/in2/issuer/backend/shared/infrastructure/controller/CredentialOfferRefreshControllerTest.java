package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.application.workflow.CredentialOfferRefreshWorkflow;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.reactive.result.view.Rendering;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferRefreshControllerTest {

    @Mock
    private CredentialOfferRefreshWorkflow credentialOfferRefreshWorkflow;

    @InjectMocks
    private CredentialOfferRefreshController controller;

    @Test
    void shouldReturnSuccessViewOnRefresh() {
        String refreshToken = "valid-token";
        when(credentialOfferRefreshWorkflow.refreshCredentialOffer(refreshToken))
                .thenReturn(Mono.empty());

        StepVerifier.create(controller.refreshCredentialOffer(refreshToken))
                .assertNext(rendering -> assertEquals("credential-offer-refresh-success", extractViewName(rendering)))
                .verifyComplete();
    }

    @Test
    void shouldReturnErrorViewOnFailure() {
        String refreshToken = "invalid-token";
        when(credentialOfferRefreshWorkflow.refreshCredentialOffer(refreshToken))
                .thenReturn(Mono.error(new RuntimeException("Token not found")));

        StepVerifier.create(controller.refreshCredentialOffer(refreshToken))
                .assertNext(rendering -> assertEquals("credential-offer-refresh-error", extractViewName(rendering)))
                .verifyComplete();
    }

    private String extractViewName(Rendering rendering) {
        return rendering.view() instanceof String viewName ? viewName : rendering.view().toString();
    }
}
