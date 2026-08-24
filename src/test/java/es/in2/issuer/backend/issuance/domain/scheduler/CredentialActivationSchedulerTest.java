package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialActivationSchedulerTest {

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private TenantRegistryService tenantRegistryService;

    @InjectMocks
    private CredentialActivationScheduler scheduler;

    @Test
    void shouldActivateIssuedCredentials() {
        Issuance issuedCredential = Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.ISSUED)
                .build();

        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
        when(issuanceService.findIssuedReadyForActivation(any(Instant.class)))
                .thenReturn(Flux.just(issuedCredential));
        when(issuanceService.updateStatusIfCurrent(any(UUID.class), any(CredentialStatusEnum.class), any(CredentialStatusEnum.class)))
                .thenReturn(Mono.empty());

        StepVerifier.create(scheduler.activateIssuedCredentials())
                .verifyComplete();

        verify(issuanceService).updateStatusIfCurrent(eq(issuedCredential.getIssuanceId()), eq(CredentialStatusEnum.ISSUED), eq(CredentialStatusEnum.VALID));
    }

    @Test
    void shouldDoNothingWhenNoIssuedCredentialsReadyForActivation() {
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
        when(issuanceService.findIssuedReadyForActivation(any(Instant.class)))
                .thenReturn(Flux.empty());

        StepVerifier.create(scheduler.activateIssuedCredentials())
                .verifyComplete();

        verify(issuanceService, never()).updateStatusIfCurrent(any(), any(), any());
    }
}
