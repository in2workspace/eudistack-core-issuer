package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
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

@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class DraftAutoWithdrawalScheduler {

    private final IssuanceService issuanceService;
    private final IssuanceProperties issuanceProperties;
    private final TenantRegistryService tenantRegistryService;

    @Scheduled(cron = "${issuance.cleanup-cron}")
    public Mono<Void> withdrawStaleDrafts() {
        Instant cutoff = Instant.now().minus(issuanceProperties.draftMaxAgeDays(), ChronoUnit.DAYS);
        log.info("Scheduled Task - Withdrawing DRAFT issuances older than {} days (cutoff: {})",
                issuanceProperties.draftMaxAgeDays(), cutoff);

        return tenantRegistryService.getActiveTenantSchemas()
                .flatMapMany(Flux::fromIterable)
                .flatMap(tenant ->
                        issuanceService.findStaleDrafts(cutoff)
                                .flatMap(issuance -> {
                                    log.info("Withdrawing stale DRAFT issuance: {} in tenant {}", issuance.getIssuanceId(), tenant);
                                    issuance.setCredentialStatus(CredentialStatusEnum.WITHDRAWN);
                                    return issuanceService.updateIssuance(issuance);
                                })
                                .then()
                                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                                .onErrorResume(e -> {
                                    log.warn("Scheduler skipped tenant '{}': {}", tenant, e.getMessage());
                                    return Mono.empty();
                                })
                )
                .then()
                .doOnSuccess(v -> log.info("Scheduled Task - Draft auto-withdrawal completed"))
                .onErrorResume(e -> {
                    log.warn("Scheduler withdrawal skipped: {}", e.getMessage());
                    return Mono.empty();
                });
    }

}
