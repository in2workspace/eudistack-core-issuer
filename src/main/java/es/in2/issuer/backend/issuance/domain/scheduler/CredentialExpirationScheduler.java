package es.in2.issuer.backend.issuance.domain.scheduler;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.EmailService;
import es.in2.issuer.backend.shared.domain.service.IssuanceService;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.EXPIRED;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class CredentialExpirationScheduler {

    private final IssuanceRepository issuanceRepository;
    private final IssuanceService issuanceService;
    private final EmailService emailService;
    private final TenantRegistryService tenantRegistryService;

    @Scheduled(cron = "0 0 1 * * ?") // Every day at 1:00 AM
    public Mono<Void> checkAndExpireCredentials() {
        log.info("Scheduled Task - Executing checkAndExpireCredentials at: {}", Instant.now());

        return tenantRegistryService.getActiveTenantSchemas()
                .flatMapMany(Flux::fromIterable)
                .flatMap(tenant ->
                        issuanceRepository.findAll()
                                .flatMap(issuance -> isExpiredAndNotAlreadyMarked(issuance)
                                        .filter(Boolean::booleanValue)
                                        .flatMap(expired -> expireCredential(issuance)
                                                .then(issuanceService.extractCredentialId(issuance)
                                                        .defaultIfEmpty(issuance.getIssuanceId().toString())
                                                        .flatMap(credentialId -> emailService.sendCredentialStatusChangeNotification(
                                                                issuance.getEmail(),
                                                                credentialId,
                                                                issuance.getCredentialType(),
                                                                EXPIRED.toString()
                                                        ))
                                                        .onErrorResume(e -> {
                                                            log.warn("Failed to send expiration email for issuanceId={}: {}",
                                                                    issuance.getIssuanceId(), e.toString());
                                                            return Mono.empty();
                                                        }))))
                                .then()
                                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                                .onErrorResume(e -> {
                                    log.warn("Scheduler skipped tenant '{}': {}", tenant, e.getMessage());
                                    return Mono.empty();
                                })
                )
                .then()
                .onErrorResume(e -> {
                    log.warn("Scheduler expiration skipped: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    private Mono<Boolean> isExpiredAndNotAlreadyMarked(Issuance issuance) {
        return Mono.justOrEmpty(issuance.getValidUntil())
                .map(validUntil ->
                        validUntil.toInstant().isBefore(Instant.now())
                                && issuance.getCredentialStatus() != CredentialStatusEnum.EXPIRED
                )
                .defaultIfEmpty(false);
    }

    private Mono<Issuance> expireCredential(Issuance issuance) {
        if (issuance.getCredentialStatus() != CredentialStatusEnum.EXPIRED) {
            issuance.setCredentialStatus(CredentialStatusEnum.EXPIRED);
            log.info("Expiring credential in issuance with ID: {} - New state: {}",
                    issuance.getIssuanceId(),
                    issuance.getCredentialStatus());
            return issuanceRepository.save(issuance);
        }
        return Mono.empty();
    }

}
