package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.EXPIRED;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CredentialExpirationSchedulerImplTest {

    @Mock private IssuanceRepository issuanceRepository;
    @Mock private IssuanceService issuanceService;
    @Mock private EmailService emailService;

    @InjectMocks
    private CredentialExpirationScheduler credentialExpirationScheduler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldExpireCredentialsWhenValidUntilHasPassed() {
        Issuance credential = new Issuance();
        credential.setIssuanceId(UUID.randomUUID());
        credential.setCredentialType("learcredential.employee.w3c.4");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setEmail("to@example.com");
        credential.setOrganizationIdentifier("VATES-A15456585");
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(issuanceRepository.findAll()).thenReturn(Flux.just(credential));
        when(issuanceRepository.save(any(Issuance.class)))
                .thenAnswer(invocation -> {
                    Issuance cp = invocation.getArgument(0);
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });
        when(issuanceService.extractCredentialId(any(Issuance.class)))
                .thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        Instant baseline = Instant.now();

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(issuanceRepository, atLeastOnce()).save(argThat(updated -> {
            Instant ua = updated.getUpdatedAt();
            return updated.getCredentialStatus() == EXPIRED
                    && ua != null
                    && ua.isAfter(baseline.minusSeconds(1));
        }));
    }

    @Test
    void shouldSendEmailWhenCredentialExpires() {
        Issuance credential = new Issuance();
        credential.setIssuanceId(UUID.randomUUID());
        credential.setCredentialType("learcredential.employee.w3c.4");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setEmail("to@example.com");
        credential.setOrganizationIdentifier("VATES-A15456585");
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(issuanceRepository.findAll()).thenReturn(Flux.just(credential));
        when(issuanceRepository.save(any(Issuance.class)))
                .thenAnswer(invocation -> {
                    Issuance cp = invocation.getArgument(0);
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });
        when(issuanceService.extractCredentialId(any(Issuance.class)))
                .thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .verifyComplete();

        verify(emailService, times(1)).sendCredentialStatusChangeNotification(
                "to@example.com", "cred-123", "learcredential.employee.w3c.4", "EXPIRED"
        );
    }

    @Test
    void shouldNotExpireCredentialsIfValidUntilHasNotPassed() {
        Issuance credential = new Issuance();
        credential.setIssuanceId(UUID.randomUUID());
        credential.setCredentialType("learcredential.employee.w3c.4");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().plusSeconds(60)));

        when(issuanceRepository.findAll()).thenReturn(Flux.just(credential));

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(issuanceRepository, never()).save(any(Issuance.class));
        verify(emailService, never()).sendCredentialStatusChangeNotification(any(), any(), any(), any());

        assertEquals(CredentialStatusEnum.VALID, credential.getCredentialStatus());
        assertNull(credential.getUpdatedAt(), "updatedAt should remain null because save() was never called");
    }
}
