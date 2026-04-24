package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialOfferRefreshWorkflowImplTest {

    @Mock
    private IssuanceService issuanceService;
    @Mock
    private CredentialOfferService credentialOfferService;

    @InjectMocks
    private CredentialOfferRefreshWorkflowImpl workflow;

    @Test
    void shouldRefreshCredentialOfferForDraftProcedure() {
        String credentialOfferRefreshToken = "valid-refresh-token";
        UUID issuanceId = UUID.randomUUID();

        Issuance issuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialType("learcredential.employee.w3c.4")
                .email("test@example.com")
                .build();

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(credentialOfferRefreshToken))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq("learcredential.employee.w3c.4"),
                eq("authorization_code"), eq("test@example.com"),
                eq("email"), eq(credentialOfferRefreshToken), eq("https://test.example/issuer")))
                .thenReturn(Mono.just(CredentialOfferResult.builder().build()));

        StepVerifier.create(workflow.refreshCredentialOffer(credentialOfferRefreshToken, "https://test.example/issuer"))
                .verifyComplete();

        verify(credentialOfferService).createAndDeliverCredentialOffer(
                eq(issuanceId.toString()), eq("learcredential.employee.w3c.4"),
                eq("authorization_code"), eq("test@example.com"),
                eq("email"), eq(credentialOfferRefreshToken), eq("https://test.example/issuer"));
    }

    @Test
    void shouldRejectRefreshForNonDraftProcedure() {
        String credentialOfferRefreshToken = "valid-refresh-token";

        Issuance issuance = Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.VALID)
                .build();

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(credentialOfferRefreshToken))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(credentialOfferRefreshToken, "https://test.example/issuer"))
                .expectErrorMatches(ex -> ex instanceof ResponseStatusException rse
                        && rse.getStatusCode().value() == 410)
                .verify();
    }

    @Test
    void shouldRejectRefreshForUnknownToken() {
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken("unknown"))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.refreshCredentialOffer("unknown", "https://test.example/issuer"))
                .expectErrorMatches(ex -> ex instanceof ResponseStatusException rse
                        && rse.getStatusCode().value() == 404)
                .verify();
    }
}
