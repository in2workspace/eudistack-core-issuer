package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.backoffice.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.model.dto.*;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.repository.CredentialOfferCacheRepository;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
import es.in2.issuer.backend.shared.domain.service.DeliveryService;
import es.in2.issuer.backend.shared.domain.service.GrantsService;
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
    private CredentialProcedureService credentialProcedureService;
    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;
    @Mock
    private GrantsService grantsService;
    @Mock
    private CredentialOfferService credentialOfferService;
    @Mock
    private CredentialOfferCacheRepository credentialOfferCacheRepository;
    @Mock
    private DeliveryService deliveryService;

    @InjectMocks
    private CredentialOfferRefreshWorkflowImpl workflow;

    @Test
    void shouldRefreshCredentialOfferForDraftProcedure() {
        String refreshToken = "valid-refresh-token";
        UUID procedureId = UUID.randomUUID();
        String transactionCode = "new-tx-code";
        String preAuthCode = "new-pre-auth-code";
        String credentialOfferUri = "openid-credential-offer://...";

        CredentialProcedure procedure = CredentialProcedure.builder()
                .procedureId(procedureId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .credentialType("LEARCredentialEmployee")
                .email("test@example.com")
                .build();

        CredentialOfferGrants grants = CredentialOfferGrants.builder()
                .preAuthorizedCode(PreAuthorizedCodeGrant.builder()
                        .preAuthorizedCode(preAuthCode)
                        .txCode(TxCode.builder().length(4).inputMode("numeric").build())
                        .build())
                .build();
        GrantsResult grantsResult = new GrantsResult(grants, "1234");

        when(credentialProcedureService.getCredentialProcedureByRefreshToken(refreshToken))
                .thenReturn(Mono.just(procedure));
        when(deferredCredentialMetadataService.updateTransactionCodeInDeferredCredentialMetadata(procedureId.toString()))
                .thenReturn(Mono.just(transactionCode));
        when(grantsService.generateGrants(anyString(), any()))
                .thenReturn(Mono.just(grantsResult));
        when(deferredCredentialMetadataService.updateAuthServerNonceByTransactionCode(transactionCode, preAuthCode))
                .thenReturn(Mono.empty());
        when(credentialOfferService.buildCredentialOffer(anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(CredentialOfferData.builder().build()));
        when(credentialOfferCacheRepository.saveCustomCredentialOffer(any()))
                .thenReturn(Mono.just("cache-nonce"));
        when(credentialOfferService.createCredentialOfferUriResponse(anyString()))
                .thenReturn(Mono.just(credentialOfferUri));
        when(credentialProcedureService.getCredentialOfferEmailInfoByProcedureId(procedureId.toString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("test@example.com", "Org")));
        when(deliveryService.deliver(anyString(), anyString(), anyString(), any()))
                .thenReturn(Mono.just(IssuanceResponse.builder().build()));

        StepVerifier.create(workflow.refreshCredentialOffer(refreshToken))
                .verifyComplete();

        verify(deferredCredentialMetadataService).updateTransactionCodeInDeferredCredentialMetadata(procedureId.toString());
        verify(grantsService).generateGrants(anyString(), any());
        verify(deliveryService).deliver(eq("email"), eq(credentialOfferUri), eq(refreshToken), any());
    }

    @Test
    void shouldRejectRefreshForNonDraftProcedure() {
        String refreshToken = "valid-refresh-token";

        CredentialProcedure procedure = CredentialProcedure.builder()
                .procedureId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.VALID)
                .build();

        when(credentialProcedureService.getCredentialProcedureByRefreshToken(refreshToken))
                .thenReturn(Mono.just(procedure));

        StepVerifier.create(workflow.refreshCredentialOffer(refreshToken))
                .expectErrorMatches(ex -> ex instanceof ResponseStatusException rse
                        && rse.getStatusCode().value() == 410)
                .verify();
    }

    @Test
    void shouldRejectRefreshForUnknownToken() {
        when(credentialProcedureService.getCredentialProcedureByRefreshToken("unknown"))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.refreshCredentialOffer("unknown"))
                .expectErrorMatches(ex -> ex instanceof ResponseStatusException rse
                        && rse.getStatusCode().value() == 404)
                .verify();
    }
}
