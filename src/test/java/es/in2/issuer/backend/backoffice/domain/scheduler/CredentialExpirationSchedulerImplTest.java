package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.dto.CredentialOfferEmailNotificationInfo;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
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

    @Mock private CredentialProcedureRepository credentialProcedureRepository;
    @Mock private ProcedureService procedureService;
    @Mock private EmailService emailService;

    @InjectMocks
    private CredentialExpirationScheduler credentialExpirationScheduler;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldExpireCredentialsWhenValidUntilHasPassed() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure cp = invocation.getArgument(0);
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });
        when(procedureService.extractCredentialId(any(CredentialProcedure.class)))
                .thenReturn(Mono.just("cred-123"));
        when(procedureService.findCredentialOfferEmailInfoByProcedureId(anyString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("to@example.com", "ACME Corp")));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), any(), anyString()))
                .thenReturn(Mono.empty());

        Instant baseline = Instant.now();

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(credentialProcedureRepository, atLeastOnce()).save(argThat(updated -> {
            Instant ua = updated.getUpdatedAt();
            return updated.getCredentialStatus() == EXPIRED
                    && ua != null
                    && ua.isAfter(baseline.minusSeconds(1));
        }));
    }

    @Test
    void shouldSendEmailWhenCredentialExpires() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().minusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenAnswer(invocation -> {
                    CredentialProcedure cp = invocation.getArgument(0);
                    cp.setUpdatedAt(Instant.now());
                    return Mono.just(cp);
                });
        when(procedureService.extractCredentialId(any(CredentialProcedure.class)))
                .thenReturn(Mono.just("cred-123"));
        when(procedureService.findCredentialOfferEmailInfoByProcedureId(anyString()))
                .thenReturn(Mono.just(new CredentialOfferEmailNotificationInfo("to@example.com", "ACME Corp")));
        when(emailService.sendCredentialStatusChangeNotification(anyString(), anyString(), anyString(), any(), anyString()))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .verifyComplete();

        verify(emailService, times(1)).sendCredentialStatusChangeNotification(
                "to@example.com", "ACME Corp", "cred-123", "LEARCredentialEmployee", "EXPIRED"
        );
    }

    @Test
    void shouldNotExpireCredentialsIfValidUntilHasNotPassed() {
        CredentialProcedure credential = new CredentialProcedure();
        credential.setProcedureId(UUID.randomUUID());
        credential.setCredentialType("LEARCredentialEmployee");
        credential.setCredentialStatus(CredentialStatusEnum.VALID);
        credential.setValidUntil(Timestamp.from(Instant.now().plusSeconds(60)));

        when(credentialProcedureRepository.findAll()).thenReturn(Flux.just(credential));

        StepVerifier.create(credentialExpirationScheduler.checkAndExpireCredentials())
                .expectSubscription()
                .verifyComplete();

        verify(credentialProcedureRepository, never()).save(any(CredentialProcedure.class));
        verify(emailService, never()).sendCredentialStatusChangeNotification(any(), any(), any(), any(), any());

        assertEquals(CredentialStatusEnum.VALID, credential.getCredentialStatus());
        assertNull(credential.getUpdatedAt(), "updatedAt should remain null because save() was never called");
    }
}
