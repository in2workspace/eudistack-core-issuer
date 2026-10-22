package es.in2.issuer.backend.oidc4vci.application.workflow.impl;

import es.in2.issuer.backend.oidc4vci.domain.exception.CredentialOfferExpiredException;
import es.in2.issuer.backend.oidc4vci.domain.service.CredentialOfferService;
import es.in2.issuer.backend.shared.domain.exception.CredentialOfferNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.EmailCommunicationException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferResult;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.enums.DeliveryMode;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.AUTHORIZATION_CODE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialOfferRefreshWorkflowImplTest {

    private static final String CREDENTIAL_OFFER_REFRESH_TOKEN = "valid-refresh-token";
    private static final String UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN = "unknown-refresh-token";
    private static final String PUBLIC_ISSUER_BASE_URL = "https://test.example/issuer";
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";
    private static final String EMAIL = "test@example.com";

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private CredentialOfferService credentialOfferService;

    @Spy
    private RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    @InjectMocks
    private CredentialOfferRefreshWorkflowImpl workflow;

    @Test
    void refreshCredentialOffer_MailSent_ShouldStageAReissuedOfferSentSuccess() {
        // Arrange
        UUID issuanceId = UUID.randomUUID();
        Instant offerExpiry = Instant.parse("2026-10-21T10:10:00Z");
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, AUTHORIZATION_CODE)));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(CredentialOfferResult.builder().offerExpiresAt(offerExpiry).build()));

        // Act
        Mono<Void> refreshed = workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL);

        // Assert
        StepVerifier.create(refreshed).verifyComplete();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditEventType.CREDENTIAL_OFFER_SENT, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("Reissued", entry.details().get("offer_kind"));
        assertEquals(EMAIL, entry.details().get("recipient_email"));
        assertEquals("issuance:" + issuanceId, entry.resource());
        assertEquals(List.of(issuanceId.toString()), auditTrail.correlationIds());
    }

    @Test
    void refreshCredentialOffer_MailBounced_ShouldStageTheFailureAndStillFailTheRequest() {
        // Arrange
        UUID issuanceId = UUID.randomUUID();
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, AUTHORIZATION_CODE)));
        when(credentialOfferService.createAndDeliverCredentialOffer(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(Mono.just(CredentialOfferResult.builder().emailError("smtp refused").build()));

        // Act
        Mono<Void> refreshed = workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL);

        // Assert
        StepVerifier.create(refreshed).expectError(EmailCommunicationException.class).verify();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertEquals(AuditResult.FAILURE, entry.result());
        assertEquals("MailDeliveryFailed", entry.reason());
    }

    @Test
    void refreshCredentialOffer_IssuanceNotInDraft_ShouldStageNothingBecauseTheRejectionHasNoCatalogueReason() {
        // Arrange
        UUID issuanceId = UUID.randomUUID();
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(buildIssuance(issuanceId, CredentialStatusEnum.VALID, AUTHORIZATION_CODE)));

        // Act
        Mono<Void> refreshed = workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL);

        // Assert
        StepVerifier.create(refreshed).expectError(CredentialOfferExpiredException.class).verify();
        assertTrue(auditTrail.all().isEmpty());
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsDraft_ShouldCreateAndDeliverCredentialOffer() {
        UUID issuanceId = UUID.randomUUID();
        Issuance issuance = buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                issuanceId.toString(),
                CREDENTIAL_TYPE,
                AUTHORIZATION_CODE,
                EMAIL,
                DeliveryMode.EMAIL.value,
                CREDENTIAL_OFFER_REFRESH_TOKEN,
                PUBLIC_ISSUER_BASE_URL))
                .thenReturn(Mono.just(CredentialOfferResult.builder().build()));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .verifyComplete();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                issuanceId.toString(),
                CREDENTIAL_TYPE,
                AUTHORIZATION_CODE,
                EMAIL,
                DeliveryMode.EMAIL.value,
                CREDENTIAL_OFFER_REFRESH_TOKEN,
                PUBLIC_ISSUER_BASE_URL);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsDraft_ShouldReusePersistedPreAuthorizedGrant() {
        UUID issuanceId = UUID.randomUUID();
        String preAuthGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
        Issuance issuance = buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, preAuthGrant);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                issuanceId.toString(),
                CREDENTIAL_TYPE,
                preAuthGrant,
                EMAIL,
                DeliveryMode.EMAIL.value,
                CREDENTIAL_OFFER_REFRESH_TOKEN,
                PUBLIC_ISSUER_BASE_URL))
                .thenReturn(Mono.just(CredentialOfferResult.builder().build()));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .verifyComplete();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                issuanceId.toString(),
                CREDENTIAL_TYPE,
                preAuthGrant,
                EMAIL,
                DeliveryMode.EMAIL.value,
                CREDENTIAL_OFFER_REFRESH_TOKEN,
                PUBLIC_ISSUER_BASE_URL);
    }

    @Test
    void refreshCredentialOffer_WhenCredentialOfferRefreshTokenIsUnknown_ShouldReturnNotFound() {
        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.empty());

        StepVerifier.create(workflow.refreshCredentialOffer(UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .expectErrorMatches(error -> error instanceof CredentialOfferNotFoundException
                        && "Invalid or unknown credential offer refresh token"
                        .equals(error.getMessage()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(UNKNOWN_CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsValid_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.VALID, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .expectErrorMatches(error -> error instanceof CredentialOfferExpiredException
                        && "This credential offer can no longer be refreshed"
                        .equals(error.getMessage()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsIssued_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.ISSUED, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .expectErrorMatches(error -> error instanceof CredentialOfferExpiredException
                        && "This credential offer can no longer be refreshed"
                        .equals(error.getMessage()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsRevoked_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.REVOKED, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .expectErrorMatches(error -> error instanceof CredentialOfferExpiredException
                        && "This credential offer can no longer be refreshed"
                        .equals(error.getMessage()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenIssuanceIsWithdrawn_ShouldReturnGone() {
        Issuance issuance = buildIssuance(UUID.randomUUID(), CredentialStatusEnum.WITHDRAWN, AUTHORIZATION_CODE);

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .expectErrorMatches(error -> error instanceof CredentialOfferExpiredException
                        && "This credential offer can no longer be refreshed"
                        .equals(error.getMessage()))
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verifyNoInteractions(credentialOfferService);
    }

    @Test
    void refreshCredentialOffer_WhenCreateAndDeliverCredentialOfferFails_ShouldPropagateError() {
        UUID issuanceId = UUID.randomUUID();
        Issuance issuance = buildIssuance(issuanceId, CredentialStatusEnum.DRAFT, AUTHORIZATION_CODE);
        RuntimeException expectedException = new RuntimeException("Credential offer delivery failed");

        when(issuanceService.getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN))
                .thenReturn(Mono.just(issuance));
        when(credentialOfferService.createAndDeliverCredentialOffer(
                issuanceId.toString(),
                CREDENTIAL_TYPE,
                AUTHORIZATION_CODE,
                EMAIL,
                DeliveryMode.EMAIL.value,
                CREDENTIAL_OFFER_REFRESH_TOKEN,
                PUBLIC_ISSUER_BASE_URL))
                .thenReturn(Mono.error(expectedException));

        StepVerifier.create(workflow.refreshCredentialOffer(CREDENTIAL_OFFER_REFRESH_TOKEN, PUBLIC_ISSUER_BASE_URL))
                .expectErrorMatches(error -> error == expectedException)
                .verify();

        verify(issuanceService).getIssuanceByCredentialOfferRefreshToken(CREDENTIAL_OFFER_REFRESH_TOKEN);
        verify(credentialOfferService).createAndDeliverCredentialOffer(
                issuanceId.toString(),
                CREDENTIAL_TYPE,
                AUTHORIZATION_CODE,
                EMAIL,
                DeliveryMode.EMAIL.value,
                CREDENTIAL_OFFER_REFRESH_TOKEN,
                PUBLIC_ISSUER_BASE_URL);
    }

    private Issuance buildIssuance(UUID issuanceId, CredentialStatusEnum credentialStatus, String grantType) {
        return Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(credentialStatus)
                .credentialType(CREDENTIAL_TYPE)
                .email(EMAIL)
                .grantType(grantType)
                .build();
    }
}