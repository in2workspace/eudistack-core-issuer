package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Detects credentials where the Wallet started the delivery flow
 * (deliveryAttemptedAt is set) but never confirmed receipt (still in DRAFT).
 * Sends an informative email to the mandatee so they can retry via
 * the refresh link in the original credential offer email.
 */
@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class DeliveryTimeoutScheduler {

    private final IssuanceService issuanceService;
    private final IssuanceProperties issuanceProperties;
    private final TenantRegistryService tenantRegistryService;
    private final EmailService emailService;

    @Scheduled(cron = "${issuance.delivery-timeout-cron}")
    public Mono<Void> detectFailedDeliveries() {
        Instant cutoff = Instant.now().minus(issuanceProperties.deliveryTimeoutMinutes(), ChronoUnit.MINUTES);
        log.info("Scheduled Task - Checking for failed deliveries (cutoff: {})", cutoff);

        return tenantRegistryService.getActiveTenantSchemas()
                .flatMapMany(Flux::fromIterable)
                .flatMap(tenant ->
                        issuanceService.findFailedDeliveries(cutoff)
                                .flatMap(issuance -> {
                                    log.info("Delivery timeout detected for issuance: {} in tenant {}", issuance.getIssuanceId(), tenant);
                                    // Clear the flag so we don't re-notify on next run
                                    issuance.setDeliveryAttemptedAt(null);
                                    return issuanceService.updateIssuance(issuance)
                                            .flatMap(saved -> emailService.sendCredentialFailureNotification(
                                                    saved.getEmail(),
                                                    "Credential delivery was not completed within the expected time."
                                            ).onErrorResume(e -> {
                                                log.warn("Failed to send delivery timeout email for issuance {}: {}", saved.getIssuanceId(), e.getMessage());
                                                return Mono.empty();
                                            }));
                                })
                                .then()
                                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                                .onErrorResume(e -> {
                                    log.warn("Scheduler skipped tenant '{}': {}", tenant, e.getMessage());
                                    return Mono.empty();
                                })
                )
                .then()
                .doOnSuccess(v -> log.info("Scheduled Task - Delivery timeout check completed"))
                .onErrorResume(e -> {
                    log.warn("Scheduler delivery timeout skipped: {}", e.getMessage());
                    return Mono.empty();
                });
    }
}
