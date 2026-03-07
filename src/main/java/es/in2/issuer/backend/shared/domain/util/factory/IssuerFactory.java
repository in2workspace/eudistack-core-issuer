package es.in2.issuer.backend.shared.domain.util.factory;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.signing.domain.model.port.SignerConfig;
import es.in2.issuer.backend.signing.domain.model.port.SigningRuntimeProperties;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Date;

import static es.in2.issuer.backend.shared.domain.util.Constants.*;

@Component
@RequiredArgsConstructor
@Slf4j
public class IssuerFactory {

    private static final String IN_MEMORY_PROVIDER = "in-memory";

    private final SignerConfig signerConfig;
    private final QtspIssuerService qtspIssuerService;
    private final SigningRuntimeProperties signingRuntimeProperties;

    private boolean isLocalProvider() {
        return IN_MEMORY_PROVIDER.equalsIgnoreCase(signingRuntimeProperties.getProvider());
    }

    /**
     * Detailed issuer creation without post-recover side-effects.
     * - Local (in-memory) or server mode: local issuer
     * - Remote mode: remote flow, retries, errors are propagated
     */
    public Mono<DetailedIssuer> createDetailedIssuer() {
        log.debug("IssuerFactory: createDetailedIssuer");
        return isLocalProvider() || qtspIssuerService.isServerMode()
                ? Mono.just(buildLocalDetailedIssuer())
                : createRemoteDetailedIssuer();
    }

    /**
     * Simple issuer creation without post-recover side-effects.
     * - Local (in-memory) or server mode: local issuer
     * - Remote mode: remote flow, retries, errors are propagated
     */
    public Mono<SimpleIssuer> createSimpleIssuer() {
        log.debug("IssuerFactory: createSimpleIssuer");
        return isLocalProvider() || qtspIssuerService.isServerMode()
                ? Mono.just(buildLocalSimpleIssuer())
                : createRemoteDetailedIssuer()
                .map(detailed -> SimpleIssuer.builder()
                        .id(detailed.getId())
                        .build());
    }

    private DetailedIssuer buildLocalDetailedIssuer() {
        return DetailedIssuer.builder()
                .organizationIdentifier(signerConfig.getOrganizationIdentifier())
                .organization(signerConfig.getOrganization())
                .country(signerConfig.getCountry())
                .commonName(signerConfig.getCommonName())
                .serialNumber(signerConfig.getSerialNumber())
                .build();
    }

    private SimpleIssuer buildLocalSimpleIssuer() {
        return SimpleIssuer.builder()
                .id(signerConfig.getOrganizationIdentifier())
                .build();
    }

    /**
     * Remote flow used by the "no notify on error" methods:
     * - retries recoverable errors
     * - propagates the error downstream if it still fails
     */
    private Mono<DetailedIssuer> createRemoteDetailedIssuer() {
        log.debug("IssuerFactory: createRemoteDetailedIssuer");
        return remoteIssuerCoreFlow()
                .retryWhen(buildRetrySpec())
                .doOnError(err ->
                        log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage())
                );
    }

    /**
     * Core remote signature flow: validate -> token -> certInfo -> extract issuer
     */
    private Mono<DetailedIssuer> remoteIssuerCoreFlow() {
        return qtspIssuerService.resolveRemoteDetailedIssuer();
    }

    private Retry buildRetrySpec() {
        return Retry.backoff(3, Duration.ofSeconds(1))
                .maxBackoff(Duration.ofSeconds(5))
                .jitter(0.5)
                .filter(QtspRetryPolicy::isRecoverable)
                .doBeforeRetry(rs -> log.info("Retry #{} for remote signature", rs.totalRetries() + 1));
    }
}