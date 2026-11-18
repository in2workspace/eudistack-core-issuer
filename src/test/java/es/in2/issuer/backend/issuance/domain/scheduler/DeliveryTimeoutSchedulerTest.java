package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.spi.RecordingAuditTrail;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeliveryTimeoutSchedulerTest {

    @Mock
    private IssuanceService issuanceService;
    @Mock
    private IssuanceProperties issuanceProperties;
    @Mock
    private TenantRegistryService tenantRegistryService;
    @Mock
    private EmailService emailService;
    @Spy
    private RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    @InjectMocks
    private DeliveryTimeoutScheduler scheduler;

    @Test
    void detectFailedDeliveries_opensTheAuditContextOfEachTenantBecauseTheMailIsAnExternalSystemAccess() {
        // Arrange
        when(issuanceProperties.deliveryTimeoutMinutes()).thenReturn(15);
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("sandbox", "kpmg")));
        when(issuanceService.findFailedDeliveries(any(Instant.class))).thenReturn(Flux.empty());

        // Act
        Mono<Void> detected = scheduler.detectFailedDeliveries();

        // Assert
        StepVerifier.create(detected).verifyComplete();
        assertEquals(List.of("sandbox/issuer", "kpmg/issuer"), auditTrail.systemScopes());
    }
}
