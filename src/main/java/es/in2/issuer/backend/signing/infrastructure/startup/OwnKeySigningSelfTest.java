package es.in2.issuer.backend.signing.infrastructure.startup;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.signing.infrastructure.adapter.KmsOwnKeySigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
import es.in2.issuer.backend.signing.infrastructure.properties.KmsSigningProperties;
import es.in2.issuer.backend.signing.infrastructure.properties.SigningSelfTestProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Signs a fixed probe for every active own-key tenant once the application is ready, so a key that
 * cannot sign shows up in the logs at startup instead of at the first issuance (EUD-289 AC-18).
 *
 * <p>It is purely informative and never prevents or delays startup (NFR-4): it runs on a bounded
 * scheduler after {@link ApplicationReadyEvent}, each tenant has a timeout, and every error is
 * swallowed. Unless configured, the timeout covers the worst case of a KMS call with all its
 * retries, so a slow KMS is reported as {@code PROVIDER_UNAVAILABLE} and not cut short. QTSP tenants are skipped: no QTSP is called at startup. The probe goes through
 * {@link KmsOwnKeySigningProvider}, which verifies the signature against the stored certificate.
 * The probe payload and the signature are never logged. Each own-key tenant's outcome is also
 * recorded in the audit trail (event {@code signing.self_test}).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OwnKeySigningSelfTest {

    static final String PROBE_PAYLOAD = "{\"probe\":\"eud-289-startup-self-test\"}";
    private static final String PROBE_TYP = "JWT";
    private static final int TENANT_CONCURRENCY = 4;
    /** On top of the worst KMS signing time: reading the configuration and verifying the signature. */
    private static final Duration TIMEOUT_MARGIN = Duration.ofSeconds(5);

    private final TenantRegistryService tenantRegistryService;
    private final TenantSigningConfigService tenantSigningConfigService;
    private final KmsOwnKeySigningProvider kmsOwnKeySigningProvider;
    private final SigningAuditor signingAuditor;
    private final SigningSelfTestProperties properties;
    private final KmsSigningProperties kmsSigningProperties;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        if (!properties.enabled()) {
            log.info("own-key signing self-test disabled");
            return;
        }
        try {
            run().subscribeOn(Schedulers.boundedElastic()).subscribe(null, e -> { });
        } catch (RuntimeException e) {
            log.warn("own-key signing self-test could not be started: {}", e.getClass().getSimpleName());
        }
    }

    /** Never emits an error: whatever happens is logged and dropped. */
    Mono<Void> run() {
        return Mono.defer(tenantRegistryService::getActiveTenantSchemas)
                .flatMapMany(Flux::fromIterable)
                .flatMap(this::selfTest, TENANT_CONCURRENCY)
                .then()
                .onErrorResume(e -> {
                    log.warn("own-key signing self-test skipped: could not list tenants ({})",
                            e.getClass().getSimpleName());
                    return Mono.empty();
                });
    }

    private Mono<Void> selfTest(String tenant) {
        long startNanos = System.nanoTime();
        AtomicReference<String> modality = new AtomicReference<>(SigningAuditor.UNKNOWN);
        return Mono.defer(tenantSigningConfigService::getActiveSigningConfig)
                .doOnNext(config -> modality.set(config.modality() == SigningModality.OWN_KEY
                        ? SigningAuditor.OWN_KEY_MODALITY : SigningAuditor.QTSP_MODALITY))
                .filter(config -> config.modality() == SigningModality.OWN_KEY)
                .flatMap(this::probe)
                .timeout(tenantTimeout(), Mono.error(() -> new SigningException(
                        SigningFailureReason.PROVIDER_UNAVAILABLE, "own-key signing self-test timed out")))
                .doOnNext(result -> {
                    log.info("own-key signing self-test passed tenant={}", tenant);
                    signingAuditor.success(SigningAuditor.SELF_TEST_EVENT,
                            attempt(tenant, modality.get(), startNanos));
                })
                .doOnError(e -> {
                    log.warn("own-key signing self-test failed tenant={} reason={}",
                            tenant, SigningFailureReasons.of(e));
                    signingAuditor.failure(SigningAuditor.SELF_TEST_EVENT,
                            attempt(tenant, modality.get(), startNanos), e);
                })
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .onErrorResume(e -> Mono.empty())
                .then();
    }

    Duration tenantTimeout() {
        return properties.tenantTimeout() != null ? properties.tenantTimeout()
                : kmsSigningProperties.worstCaseSigningDuration().plus(TIMEOUT_MARGIN);
    }

    private Mono<SigningResult> probe(ActiveSigningConfig config) {
        SigningRequest request = SigningRequest.builder()
                .type(SigningType.JADES)
                .data(PROBE_PAYLOAD)
                .typ(PROBE_TYP)
                .ownKey(config.ownKey())
                .build();
        return kmsOwnKeySigningProvider.sign(request);
    }

    private static SigningAuditor.Attempt attempt(String tenant, String modality, long startNanos) {
        return new SigningAuditor.Attempt(tenant, "self-test", null, modality, SigningAuditor.KMS_PROVIDER,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos));
    }
}
