package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.backoffice.infrastructure.config.properties.ProcedureProperties;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DraftAutoWithdrawalSchedulerTest {

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private ProcedureProperties procedureProperties;

    @InjectMocks
    private DraftAutoWithdrawalScheduler scheduler;

    @Test
    void shouldWithdrawStaleDrafts() {
        CredentialProcedure staleDraft = CredentialProcedure.builder()
                .procedureId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .createdAt(Instant.now().minus(45, ChronoUnit.DAYS))
                .build();

        when(procedureProperties.draftMaxAgeDays()).thenReturn(30);
        when(credentialProcedureRepository.findByCredentialStatusAndCreatedAtBefore(
                eq(CredentialStatusEnum.DRAFT), any(Instant.class)))
                .thenReturn(Flux.just(staleDraft));
        when(credentialProcedureRepository.save(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(staleDraft));

        StepVerifier.create(scheduler.withdrawStaleDrafts())
                .verifyComplete();

        verify(credentialProcedureRepository).save(argThat(proc ->
                proc.getCredentialStatus() == CredentialStatusEnum.WITHDRAWN));
    }

    @Test
    void shouldDoNothingWhenNoStaleDrafts() {
        when(procedureProperties.draftMaxAgeDays()).thenReturn(30);
        when(credentialProcedureRepository.findByCredentialStatusAndCreatedAtBefore(
                eq(CredentialStatusEnum.DRAFT), any(Instant.class)))
                .thenReturn(Flux.empty());

        StepVerifier.create(scheduler.withdrawStaleDrafts())
                .verifyComplete();

        verify(credentialProcedureRepository, never()).save(any());
    }
}
