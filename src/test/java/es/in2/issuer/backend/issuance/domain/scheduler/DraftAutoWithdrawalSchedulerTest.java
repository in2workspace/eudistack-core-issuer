package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DraftAutoWithdrawalSchedulerTest {

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private IssuanceProperties procedureProperties;

    @InjectMocks
    private DraftAutoWithdrawalScheduler scheduler;

    @Test
    void shouldWithdrawStaleDrafts() {
        Issuance staleDraft = Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .createdAt(Instant.now().minus(45, ChronoUnit.DAYS))
                .build();

        when(procedureProperties.draftMaxAgeDays()).thenReturn(30);
        when(issuanceService.findStaleDrafts(any(Instant.class)))
                .thenReturn(Flux.just(staleDraft));
        when(issuanceService.updateIssuance(any(Issuance.class)))
                .thenReturn(Mono.just(staleDraft));

        StepVerifier.create(scheduler.withdrawStaleDrafts())
                .verifyComplete();

        verify(issuanceService).updateIssuance(argThat(proc ->
                proc.getCredentialStatus() == CredentialStatusEnum.WITHDRAWN));
    }

    @Test
    void shouldDoNothingWhenNoStaleDrafts() {
        when(procedureProperties.draftMaxAgeDays()).thenReturn(30);
        when(issuanceService.findStaleDrafts(any(Instant.class)))
                .thenReturn(Flux.empty());

        StepVerifier.create(scheduler.withdrawStaleDrafts())
                .verifyComplete();

        verify(issuanceService, never()).updateIssuance(any());
    }
}
