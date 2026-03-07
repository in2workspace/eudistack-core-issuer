package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.issuance.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.GrantsService;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
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
    private GrantsService grantsService;
    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;
    @Mock
    private EmailService emailService;
    @Mock
    private IssuerProperties appConfig;

    @InjectMocks
    private CredentialOfferRefreshWorkflowImpl workflow;

    @Test
    void shouldRefreshCredentialOfferForDraftProcedure() {
        String credentialOfferRefreshToken = "valid-refresh-token";
        UUID issuanceId = UUID.randomUUID();
        String transactionCode = "new-tx-code";
        String preAuthCode = "new-pre-auth-code";
        String credentialOfferUri = "openid-credential-offer://...";

        Issuance issuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialType("LEARCredentialEmployee")
                .email("test@example.com")
                .build();

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode(preAuthCode)
                        .txCode(TxCode.builder().length(6).inputMode("numeric").build())
                        .build())
                .build();
        GrantsResult grantsResult = new GrantsResult(grants, "1234");

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(credentialOfferRefreshToken))
                .thenReturn(Mono.just(issuance));
        when(grantsService.createGrants(anyString(), any()))
                .thenReturn(Mono.just(grantsResult));
        when(credentialOfferService.buildCredentialOffer(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(CredentialOfferData.builder().build()));
        when(credentialOfferCacheRepository.saveCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));
        when(credentialOfferService.createCredentialOfferUriResponse(anyString()))
                .thenReturn(Mono.just(credentialOfferUri));
        when(issuanceService.findCredentialOfferEmailInfoByIssuanceId(issuanceId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "Org")));
        when(appConfig.getIssuerBackendUrl()).thenReturn("https://issuer.example.com");
        when(appConfig.getWalletFrontendUrl()).thenReturn("https://wallet.example.com");
        when(emailService.sendCredentialOfferEmail(anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.refreshCredentialOffer(credentialOfferRefreshToken))
                .verifyComplete();

        verify(grantsService).createGrants(anyString(), any());
        verify(emailService).sendCredentialOfferEmail(eq("test@example.com"), anyString(), eq(credentialOfferUri), anyString(), eq("https://wallet.example.com"), eq("Org"));
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

        StepVerifier.create(workflow.refreshCredentialOffer(credentialOfferRefreshToken))
                .expectErrorMatches(ex -> ex instanceof ResponseStatusException rse
                        && rse.getStatusCode().value() == 410)
                .verify();
    }

    @Test
    void shouldRejectRefreshForUnknownToken() {
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken("unknown"))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.refreshCredentialOffer("unknown"))
                .expectErrorMatches(ex -> ex instanceof ResponseStatusException rse
                        && rse.getStatusCode().value() == 404)
                .verify();
    }
}
