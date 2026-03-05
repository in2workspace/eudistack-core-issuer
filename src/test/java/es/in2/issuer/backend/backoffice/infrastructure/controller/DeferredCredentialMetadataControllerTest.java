package es.in2.issuer.backend.backoffice.infrastructure.controller;

import es.in2.issuer.backend.oidc4vci.application.workflow.Oid4VciCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.model.dto.AuthServerNonceRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeferredCredentialMetadataControllerTest {

    @Mock
    private Oid4VciCredentialWorkflow oid4VciCredentialWorkflow;

    @InjectMocks
    private DeferredCredentialMetadataController deferredCredentialMetadataController;

    @Test
    void bindAccessTokenByPreAuthorizedCode() {
        // Arrange
        AuthServerNonceRequest authServerNonceRequest = new AuthServerNonceRequest("pre-authorized-code", "access-token");
        when(oid4VciCredentialWorkflow.bindAccessTokenByPreAuthorizedCode(anyString(), eq(authServerNonceRequest))).thenReturn(Mono.empty());

        // Act
        Mono<Void> result = deferredCredentialMetadataController.bindAccessTokenByPreAuthorizedCode(authServerNonceRequest);

        // Assert
        StepVerifier.create(result)
                .verifyComplete();
    }
}