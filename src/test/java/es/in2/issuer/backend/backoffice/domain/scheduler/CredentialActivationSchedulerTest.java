package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.ProcedureService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialActivationSchedulerTest {

    @Mock
    private ProcedureService procedureService;

    @InjectMocks
    private CredentialActivationScheduler scheduler;

    @Test
    void shouldActivateIssuedCredentials() {
        CredentialProcedure issuedCredential = CredentialProcedure.builder()
                .procedureId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.ISSUED)
                .build();

        when(procedureService.findIssuedReadyForActivation(any(Instant.class)))
                .thenReturn(Flux.just(issuedCredential));
        when(procedureService.updateProcedure(any(CredentialProcedure.class)))
                .thenReturn(Mono.just(issuedCredential));

        StepVerifier.create(scheduler.activateIssuedCredentials())
                .verifyComplete();

        verify(procedureService).updateProcedure(argThat(proc ->
                proc.getCredentialStatus() == CredentialStatusEnum.VALID));
    }

    @Test
    void shouldDoNothingWhenNoIssuedCredentialsReadyForActivation() {
        when(procedureService.findIssuedReadyForActivation(any(Instant.class)))
                .thenReturn(Flux.empty());

        StepVerifier.create(scheduler.activateIssuedCredentials())
                .verifyComplete();

        verify(procedureService, never()).updateProcedure(any());
    }
}
