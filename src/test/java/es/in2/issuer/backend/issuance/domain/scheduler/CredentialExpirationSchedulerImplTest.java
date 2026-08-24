package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
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
import java.util.List;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.EXPIRED;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CredentialExpirationSchedulerImplTest {

    @Mock private IssuanceRepository issuanceRepository;
    @Mock private IssuanceService issuanceService;
    @Mock private EmailService emailService;
    @Mock private TenantRegistryService tenantRegistryService;

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

        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
        when(issuanceRepository.findAllByCredentialStatusNotExpiredAndValidUntilBefore(any(Instant.class)))
                .thenReturn(Flux.just(credential));
        when(issuanceService.updateStatusIfCurrent(any(UUID.class), any(CredentialStatusEnum.class), any(CredentialStatusEnum.class)))
                .thenReturn(Mono.empty());
        when(issuanceService.extractCredentialId(any(Issuance.class)))
                .thenReturn(Mono.just("cred-123"));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(issuanceService, atLeastOnce()).updateStatusIfCurrent(eq(credential.getIssuanceId()), eq(CredentialStatusEnum.VALID), eq(EXPIRED));
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

        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
        when(issuanceRepository.findAllByCredentialStatusNotExpiredAndValidUntilBefore(any(Instant.class)))
                .thenReturn(Flux.just(credential));
        when(issuanceService.updateStatusIfCurrent(any(UUID.class), any(CredentialStatusEnum.class), any(CredentialStatusEnum.class)))
                .thenReturn(Mono.empty());
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
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
        when(issuanceRepository.findAllByCredentialStatusNotExpiredAndValidUntilBefore(any(Instant.class)))
                .thenReturn(Flux.empty());

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(issuanceService, never()).updateStatusIfCurrent(any(), any(), any());
        verify(emailService, never()).sendCredentialStatusChangeNotification(any(), any(), any(), any());
    }
}
