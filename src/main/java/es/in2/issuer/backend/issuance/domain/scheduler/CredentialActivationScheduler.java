package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class CredentialActivationScheduler {

    private final IssuanceService issuanceService;

    @Scheduled(cron = "0 */5 * * * ?") // Every 5 minutes
    public Mono<Void> activateIssuedCredentials() {
        Instant now = Instant.now();
        log.info("Scheduled Task - Activating ISSUED credentials with validFrom <= {}", now);

        return issuanceService
                .findIssuedReadyForActivation(now)
                .flatMap(issuance -> {
                    log.info("Activating credential: {} (ISSUED → VALID)", issuance.getIssuanceId());
                    issuance.setCredentialStatus(CredentialStatusEnum.VALID);
                    return issuanceService.updateIssuance(issuance);
                })
                .then()
                .doOnSuccess(v -> log.info("Scheduled Task - Credential activation completed"))
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
    }
}
