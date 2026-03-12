package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.issuance.infrastructure.config.properties.IssuanceProperties;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
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

    @Scheduled(cron = "${issuance.cleanup-cron}")
    public Mono<Void> withdrawStaleDrafts() {
        Instant cutoff = Instant.now().minus(issuanceProperties.draftMaxAgeDays(), ChronoUnit.DAYS);
        log.info("Scheduled Task - Withdrawing DRAFT issuances older than {} days (cutoff: {})",
                issuanceProperties.draftMaxAgeDays(), cutoff);

        return issuanceService
                .findStaleDrafts(cutoff)
                .flatMap(issuance -> {
                    log.info("Withdrawing stale DRAFT issuance: {}", issuance.getIssuanceId());
                    issuance.setCredentialStatus(CredentialStatusEnum.WITHDRAWN);
                    return issuanceService.updateIssuance(issuance);
                })
                .then()
                .doOnSuccess(v -> log.info("Scheduled Task - Draft auto-withdrawal completed"))
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
    }

}
