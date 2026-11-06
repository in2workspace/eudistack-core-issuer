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
import es.in2.issuer.backend.signing.domain.util.StoredCertificateInfo;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.signing.infrastructure.adapter.AwsKmsSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
import es.in2.issuer.backend.signing.infrastructure.kms.KmsSigningTiming;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Signs a fixed probe for every active own-key tenant once the application is ready, so a key that
 * cannot sign shows up in the logs at startup instead of at the first issuance.
 *
 * <p>It is purely informative and never prevents or delays startup: it runs on a bounded
 * scheduler after {@link ApplicationReadyEvent}, each tenant has a timeout, and every error is
 * swallowed. The timeout covers the worst case of a KMS call with all its retries, so a slow KMS is
 * reported as {@code PROVIDER_UNAVAILABLE} and not cut short. QTSP
 * tenants are skipped: no QTSP is called at startup. A tenant without an active configuration, of
 * either modality, is reported as {@code NO_CONFIGURATION}: it cannot issue anything. The probe goes
 * through {@link AwsKmsSigningProvider}, which verifies the signature against the certificate.
 * The probe payload and the signature are never logged. Each own-key tenant's outcome is also
 * recorded in the audit trail (event {@code signing.self_test}). A signing certificate that expires
 * within {@link #CERTIFICATE_EXPIRY_WARNING} is logged as a warning: from its expiry the issuer refuses
 * to sign with it. Timeout and warning window are fixed.
 */
@Slf4j
@Component
public class OwnKeySigningSelfTest {

    static final String PROBE_PAYLOAD = "{\"probe\":\"eud-289-startup-self-test\"}";
    private static final String PROBE_TYP = "JWT";
    private static final int TENANT_CONCURRENCY = 4;
    /** On top of the worst KMS signing time: reading the configuration and verifying the signature. */
    private static final Duration TIMEOUT_MARGIN = Duration.ofSeconds(5);
    static final Duration TENANT_TIMEOUT =
            KmsSigningTiming.DEFAULT.worstCaseSigningDuration().plus(TIMEOUT_MARGIN);
    /** Time left before the certificate expires from which the renewal warning is logged. */
    static final Duration CERTIFICATE_EXPIRY_WARNING = Duration.ofDays(30);

    private final TenantRegistryService tenantRegistryService;
    private final TenantSigningConfigService tenantSigningConfigService;
    private final AwsKmsSigningProvider awsKmsSigningProvider;
    private final SigningAuditor signingAuditor;
    private final Clock clock;
    private final Duration tenantTimeout;

    @Autowired
    public OwnKeySigningSelfTest(TenantRegistryService tenantRegistryService,
                                 TenantSigningConfigService tenantSigningConfigService,
                                 AwsKmsSigningProvider awsKmsSigningProvider,
                                 SigningAuditor signingAuditor,
                                 Clock clock) {
        this(tenantRegistryService, tenantSigningConfigService, awsKmsSigningProvider, signingAuditor, clock,
                TENANT_TIMEOUT);
    }

    /** For tests: another timeout per tenant. */
    OwnKeySigningSelfTest(TenantRegistryService tenantRegistryService,
                          TenantSigningConfigService tenantSigningConfigService,
                          AwsKmsSigningProvider awsKmsSigningProvider,
                          SigningAuditor signingAuditor,
                          Clock clock,
                          Duration tenantTimeout) {
        this.tenantRegistryService = tenantRegistryService;
        this.tenantSigningConfigService = tenantSigningConfigService;
        this.awsKmsSigningProvider = awsKmsSigningProvider;
        this.signingAuditor = signingAuditor;
        this.clock = clock;
        this.tenantTimeout = tenantTimeout;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
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
        AtomicReference<Boolean> qualified = new AtomicReference<>();
        return Mono.defer(tenantSigningConfigService::getActiveSigningConfig)
                .switchIfEmpty(Mono.defer(() -> {
                    reportMissingConfiguration(tenant, startNanos);
                    return Mono.empty();
                }))
                .doOnNext(config -> {
                    modality.set(config.modality() == SigningModality.OWN_KEY
                            ? SigningAuditor.OWN_KEY_MODALITY : SigningAuditor.QTSP_MODALITY);
                    qualified.set(SigningAuditor.qualifiedCertificate(config));
                })
                .filter(config -> config.modality() == SigningModality.OWN_KEY)
                .flatMap(config -> probe(config).doOnNext(result -> warnIfExpiringSoon(tenant, config)))
                .timeout(tenantTimeout, Mono.error(() -> new SigningException(
                        SigningFailureReason.PROVIDER_UNAVAILABLE, "own-key signing self-test timed out")))
                .doOnNext(result -> {
                    log.info("own-key signing self-test passed tenant={}", tenant);
                    signingAuditor.success(SigningAuditor.SELF_TEST_EVENT,
                            attempt(tenant, modality.get(), qualified.get(), startNanos));
                })
                .doOnError(e -> {
                    log.warn("own-key signing self-test failed tenant={} reason={}",
                            tenant, SigningFailureReasons.of(e));
                    signingAuditor.failure(SigningAuditor.SELF_TEST_EVENT,
                            attempt(tenant, modality.get(), qualified.get(), startNanos), e);
                })
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant))
                .onErrorResume(e -> Mono.empty())
                .then();
    }

    private Mono<SigningResult> probe(ActiveSigningConfig config) {
        SigningRequest request = SigningRequest.builder()
                .type(SigningType.JADES)
                .data(PROBE_PAYLOAD)
                .typ(PROBE_TYP)
                .ownKey(config.ownKey())
                .build();
        return awsKmsSigningProvider.sign(request);
    }

    private void warnIfExpiringSoon(String tenant, ActiveSigningConfig config) {
        Instant notAfter = StoredCertificateInfo.leaf(config.ownKey()).getNotAfter().toInstant();
        Duration left = Duration.between(clock.instant(), notAfter);
        if (left.compareTo(CERTIFICATE_EXPIRY_WARNING) <= 0) {
            log.warn("own-key signing certificate expires soon tenant={} notAfter={} daysLeft={}",
                    tenant, notAfter, left.toDays());
        }
    }

    private void reportMissingConfiguration(String tenant, long startNanos) {
        log.warn("signing self-test: no active signing configuration tenant={}", tenant);
        signingAuditor.failure(SigningAuditor.SELF_TEST_EVENT,
                attempt(tenant, SigningAuditor.UNKNOWN, SigningAuditor.UNKNOWN, null, startNanos),
                new SigningException(SigningFailureReason.NO_CONFIGURATION, "No active signing configuration"));
    }

    private static SigningAuditor.Attempt attempt(String tenant, String modality, Boolean qualified,
                                                  long startNanos) {
        return attempt(tenant, modality, SigningAuditor.KMS_PROVIDER, qualified, startNanos);
    }

    private static SigningAuditor.Attempt attempt(String tenant, String modality, String provider, Boolean qualified,
                                                  long startNanos) {
        return new SigningAuditor.Attempt(tenant, "self-test", null, modality, provider,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos), qualified);
    }
}
