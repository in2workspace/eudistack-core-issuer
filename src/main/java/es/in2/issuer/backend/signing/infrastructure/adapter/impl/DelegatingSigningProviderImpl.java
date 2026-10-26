package es.in2.issuer.backend.signing.infrastructure.adapter.impl;

import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.model.OwnKeySigningConfig;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.model.SigningProviderType;
import es.in2.issuer.backend.signing.domain.util.QtspRetryPolicy;
import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.signing.infrastructure.csc.config.RemoteSignatureDto;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.dto.SigningResult;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.DelegatingSigningProvider;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningAuditor;
import es.in2.issuer.backend.signing.infrastructure.adapter.SigningProviderResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Routes signing requests by the active tenant's signing modality, through {@link SigningProviderResolver}:
 * to the CSC operation configured for its QTSP, or to the KMS own-key provider. Reads signing config
 * per-tenant from the database (via {@link TenantSigningConfigService}) and injects it into the {@link
 * SigningRequest} before delegating.
 *
 * <p>There is no global fallback: if {@code tenant_signing_config} has no
 * row for the active tenant, a {@link SigningException} is thrown. Seed
 * the row via {@code seed-tenants[.stg].sql} or via the per-tenant config
 * management service (future EUDI-090).
 *
 * <p>This is the single choke point of signing: every attempt, for either modality, is recorded
 * through {@link SigningAuditor} (EUD-289 AC-19), including those that fail before a configuration
 * is resolved (modality and provider then read {@code unknown}).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DelegatingSigningProviderImpl implements DelegatingSigningProvider {

    private final TenantSigningConfigService tenantSigningConfigService;
    private final SigningProviderResolver signingProviderResolver;
    private final SigningAuditor signingAuditor;

    @Override
    public Mono<SigningResult> sign(SigningRequest request) {

        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, SigningAuditor.UNKNOWN);
            long startNanos = System.nanoTime();
            AtomicReference<ActiveSigningConfig> resolved = new AtomicReference<>();

            return Mono.justOrEmpty(request.remoteSignature())
                    .map(ActiveSigningConfig::qtsp)
                    .switchIfEmpty(Mono.defer(this::loadActiveSigningConfig))
                    .doOnNext(resolved::set)
                    .flatMap(config -> sign(request, config)
                            .onErrorResume(error -> isDisabledOwnKey(config, error),
                                    error -> reloadAndSign(request, resolved))
                            .onErrorMap(DelegatingSigningProviderImpl::classify))
                    .doOnNext(result -> signingAuditor.success(SigningAuditor.SIGN_EVENT,
                            attempt(tenant, request, resolved.get(), startNanos)))
                    .doOnError(error -> signingAuditor.failure(SigningAuditor.SIGN_EVENT,
                            attempt(tenant, request, resolved.get(), startNanos), error));
        });
    }

    /**
     * An own key that KMS no longer lets sign. When a key is replaced or withdrawn it is disabled in
     * KMS at once (EUD-289 D-3), while this instance may still hold the old configuration in cache.
     */
    private static boolean isDisabledOwnKey(ActiveSigningConfig config, Throwable error) {
        return config.modality() == SigningModality.OWN_KEY
                && SigningFailureReasons.of(error) == SigningFailureReason.KEY_UNUSABLE;
    }

    /**
     * Reads the tenant's configuration again and signs once more with it: the replacement when the key
     * was replaced, {@code NO_CONFIGURATION} when it was withdrawn. A second failure is not retried.
     */
    private Mono<SigningResult> reloadAndSign(SigningRequest request, AtomicReference<ActiveSigningConfig> resolved) {
        log.info("Own key not usable, reloading the signing configuration");
        return tenantSigningConfigService.reloadActiveSigningConfig()
                .switchIfEmpty(Mono.error(DelegatingSigningProviderImpl::noConfiguration))
                .doOnNext(resolved::set)
                .flatMap(config -> sign(request, config));
    }

    /** Audit data of one attempt: classification only, never the payload, tokens or key reference. */
    private static SigningAuditor.Attempt attempt(String tenant, SigningRequest request,
                                                  ActiveSigningConfig config, long startNanos) {
        String object = request.typ() == null ? String.valueOf(request.type())
                : request.type() + "/" + request.typ();
        String issuanceId = request.context() == null ? null : request.context().issuanceId();
        String modality = SigningAuditor.UNKNOWN;
        String provider = SigningAuditor.UNKNOWN;
        if (config != null) {
            switch (config.modality()) {
                case QTSP -> {
                    modality = SigningAuditor.QTSP_MODALITY;
                    provider = config.qtsp().provider();
                }
                case OWN_KEY -> {
                    modality = SigningAuditor.OWN_KEY_MODALITY;
                    provider = SigningAuditor.KMS_PROVIDER;
                }
            }
        }
        long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
        return new SigningAuditor.Attempt(tenant, object, issuanceId, modality, provider, durationMs);
    }

    /**
     * Coarse reason for QTSP-path failures (EUD-289 D-7): a reason already carried in the cause
     * chain is kept; otherwise a recoverable (transient) failure is {@code PROVIDER_UNAVAILABLE}.
     * Anything else stays as it is and reads as {@code OTHER}.
     */
    private static Throwable classify(Throwable error) {
        if (SigningFailureReasons.of(error) != SigningFailureReason.OTHER
                || !QtspRetryPolicy.isRecoverable(error)) {
            return error;
        }
        return new SigningException(SigningFailureReason.PROVIDER_UNAVAILABLE, error.getMessage(), error);
    }

    private Mono<ActiveSigningConfig> loadActiveSigningConfig() {

        return tenantSigningConfigService.getActiveSigningConfig()
                .switchIfEmpty(Mono.error(DelegatingSigningProviderImpl::noConfiguration));
    }

    private static SigningException noConfiguration() {
        return new SigningException(
                SigningFailureReason.NO_CONFIGURATION,
                """
                        No remote signature configuration available for this tenant.
                        Seed tenant_signing_config for the active tenant.
                        """
        );
    }

    private Mono<SigningResult> sign(SigningRequest request, ActiveSigningConfig config) {

        return switch (config.modality()) {
            case QTSP -> sign(request, config.qtsp());
            case OWN_KEY -> signingProviderResolver.resolve(SigningProviderType.AWS_KMS)
                    .sign(withOwnKey(request, config.ownKey()));
        };
    }

    private Mono<SigningResult> sign(
            SigningRequest signingRequest,
            RemoteSignatureDto remoteSignatureDto
    ) {

        validateSigningOperation(remoteSignatureDto.signingOperation());

        SigningProvider signingProvider =
                signingProviderResolver.resolveFromValue(
                        remoteSignatureDto.signingOperation()
                );

        log.info(
                "Signing via operation='{}' type='{}' url='{}'",
                remoteSignatureDto.signingOperation(),
                signingRequest.type(),
                remoteSignatureDto.url()
        );

        return signingProvider.sign(
                enrich(signingRequest, remoteSignatureDto)
        );
    }

    private void validateSigningOperation(String operation) {

        if (operation == null || operation.isBlank()) {

            throw new SigningException(
                    """
                            signingOperation is required in the QTSP configuration.
                            Set it to 'sign-hash' or 'sign-doc'.
                            """
            );
        }
    }

    private static SigningRequest withOwnKey(SigningRequest original, OwnKeySigningConfig ownKey) {

        return SigningRequest.builder()
                .type(original.type())
                .data(original.data())
                .context(original.context())
                .typ(original.typ())
                .ownKey(ownKey)
                .build();
    }

    private static SigningRequest enrich(
            SigningRequest original,
            RemoteSignatureDto cfg
    ) {

        if (original.remoteSignature() != null) {
            return original;
        }

        return SigningRequest.builder()
                .type(original.type())
                .data(original.data())
                .context(original.context())
                .typ(original.typ())
                .remoteSignature(cfg)
                .build();
    }
}