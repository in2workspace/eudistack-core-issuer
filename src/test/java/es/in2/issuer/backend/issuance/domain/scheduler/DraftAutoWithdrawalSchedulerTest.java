package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEventType;
import es.in2.issuer.backend.shared.domain.model.audit.AuditResult;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DraftAutoWithdrawalSchedulerTest {

    @Mock
    private IssuanceService issuanceService;

    @Mock
    private IssuanceProperties procedureProperties;

    @Mock
    private TenantRegistryService tenantRegistryService;

    @Mock
    private TransactionalOperator transactionalOperator;

    @Spy
    private RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    @InjectMocks
    private DraftAutoWithdrawalScheduler scheduler;

    @BeforeEach
    void setUp() {
        lenient().when(transactionalOperator.transactional(any(Mono.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void shouldWithdrawStaleDrafts() {
        Issuance staleDraft = Issuance.builder()
                .issuanceId(UUID.randomUUID())
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .createdAt(Instant.now().minus(45, ChronoUnit.DAYS))
                .build();

        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
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
    void withdrawStaleDrafts_staleDraft_stagesWithdrawnUnderTheSystemContextOfItsTenantAndItsOwnCorrelation() {
        // Arrange
        UUID issuanceId = UUID.randomUUID();
        Issuance staleDraft = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .build();
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("sandbox", "kpmg")));
        when(procedureProperties.draftMaxAgeDays()).thenReturn(30);
        when(issuanceService.findStaleDrafts(any(Instant.class))).thenReturn(Flux.just(staleDraft), Flux.empty());
        when(issuanceService.updateIssuance(any(Issuance.class))).thenReturn(Mono.just(staleDraft));

        // Act
        Mono<Void> withdrawn = scheduler.withdrawStaleDrafts();

        // Assert
        StepVerifier.create(withdrawn).verifyComplete();
        assertEquals(List.of("sandbox/issuer", "kpmg/issuer"), auditTrail.systemScopes());
        assertEquals(1, auditTrail.staged().size());
        AuditEntry entry = auditTrail.staged().getFirst();
        assertEquals(AuditEventType.ISSUANCE_WITHDRAWN, entry.type());
        assertEquals(AuditResult.SUCCESS, entry.result());
        assertEquals("issuance:" + issuanceId, entry.resource());
        assertTrue(entry.details().isEmpty());
        assertEquals(List.of(issuanceId.toString()), auditTrail.correlationIds());
    }

    @Test
    void shouldDoNothingWhenNoStaleDrafts() {
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(List.of("default")));
        when(procedureProperties.draftMaxAgeDays()).thenReturn(30);
        when(issuanceService.findStaleDrafts(any(Instant.class)))
                .thenReturn(Flux.empty());

        StepVerifier.create(scheduler.withdrawStaleDrafts())
                .verifyComplete();

        verify(issuanceService, never()).updateIssuance(any());
    }
}
