package es.in2.issuer.backend.backoffice.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.backoffice.infrastructure.config.properties.ProcedureProperties;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
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

    private final CredentialProcedureRepository credentialProcedureRepository;
    private final ProcedureProperties procedureProperties;

    @Scheduled(cron = "${procedure.cleanup-cron}")
    public Mono<Void> withdrawStaleDrafts() {
        Instant cutoff = Instant.now().minus(procedureProperties.draftMaxAgeDays(), ChronoUnit.DAYS);
        log.info("Scheduled Task - Withdrawing DRAFT procedures older than {} days (cutoff: {})",
                procedureProperties.draftMaxAgeDays(), cutoff);

        return credentialProcedureRepository
                .findByCredentialStatusAndCreatedAtBefore(CredentialStatusEnum.DRAFT, cutoff)
                .flatMap(procedure -> {
                    log.info("Withdrawing stale DRAFT procedure: {}", procedure.getProcedureId());
                    procedure.setCredentialStatus(CredentialStatusEnum.WITHDRAWN);
                    return credentialProcedureRepository.save(procedure);
                })
                .then()
                .doOnSuccess(v -> log.info("Scheduled Task - Draft auto-withdrawal completed"))
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "*"));
    }

}
