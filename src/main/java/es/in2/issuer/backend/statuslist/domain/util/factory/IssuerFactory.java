package es.in2.issuer.backend.statuslist.domain.util.factory;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;

@Component
@RequiredArgsConstructor
@Slf4j
public class IssuerFactory {

    private final IssuerCertificateService issuerCertificateService;
    private final TenantSigningConfigService tenantSigningConfigService;

    public Mono<DetailedIssuer> createDetailedIssuer() {
        log.debug("IssuerFactory: createDetailedIssuer");
        return tenantSigningConfigService.getActiveSigningConfig()
                .switchIfEmpty(Mono.error(new SigningException(SigningFailureReason.NO_CONFIGURATION,
                        "No remote signature configuration available for this tenant. " +
                        "Seed tenant_signing_config for the active tenant.")))
                .flatMap(this::resolveIssuer)
                .retryWhen(buildRetrySpec())
                .doOnError(err ->
                        log.error("Error during remote issuer creation: {}", err.getMessage(), err)
                );
    }

    private Mono<DetailedIssuer> resolveIssuer(ActiveSigningConfig config) {
        return switch (config.modality()) {
            case QTSP -> issuerCertificateService.resolveRemoteDetailedIssuer(config.qtsp());
            case OWN_KEY -> resolveOwnKeyIssuer();
        };
    }

    // TODO(EUD-289): placeholder, B4 replaces it with the issuer identity read from the stored certificate.
    private Mono<DetailedIssuer> resolveOwnKeyIssuer() {
        return Mono.error(new SigningException(
                SigningFailureReason.KEY_UNUSABLE, "own-key signing not available yet"));
    }

    public Mono<SimpleIssuer> createSimpleIssuer() {
        log.debug("IssuerFactory: createSimpleIssuer");
        return createDetailedIssuer()
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    private Retry buildRetrySpec() {
        return Retry.backoff(3, Duration.ofSeconds(1))
                .maxBackoff(Duration.ofSeconds(5))
                .jitter(0.5)
                .filter(QtspRetryPolicy::isRecoverable)
                .doBeforeRetry(rs -> log.info("Retry #{} for remote signature", rs.totalRetries() + 1));
    }
}
