package es.in2.issuer.backend.statuslist.domain.util.factory;

import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.signing.domain.service.QtspIssuerService;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.Date;

@Component
@RequiredArgsConstructor
@Slf4j
public class IssuerFactory {

    private final QtspIssuerService qtspIssuerService;

    public Mono<DetailedIssuer> createDetailedIssuer() {
        log.debug("IssuerFactory: createDetailedIssuer");
        return qtspIssuerService.resolveRemoteDetailedIssuer()
                .retryWhen(buildRetrySpec())
                .doOnError(err ->
                        log.error("Error during remote issuer creation at {}: {}", new Date(), err.getMessage())
                );
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
