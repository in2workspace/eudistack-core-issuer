package es.in2.issuer.backend.shared.infrastructure.audit;

import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Completion;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Provider;
import es.in2.issuer.backend.shared.domain.model.dto.credential.DetailedIssuer;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.shared.domain.spi.IssuanceCompletionAuditPort;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.domain.model.ActiveSigningConfig;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignatureProof;
import es.in2.issuer.backend.signing.domain.util.JwsHeaderFingerprint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/**
 * Records the {@code IssuanceCompleted} event of an attestation that is being delivered. The event is staged
 * in the transaction that is already active, so it commits or rolls back with the write that marks the
 * attestation as delivered (DT-002 RQ-01, EC-10): if the outbox insert fails, so does the delivery, and a
 * restart cannot lose the event. The caller opens the transaction.
 *
 * <p>The delivery is always reported. What cannot be learned is left out of the event and logged: the
 * signing certificate and algorithm come from the header of the signed JWS, so a signature without one (a
 * COSE one) has none, and the provider is the organization of the tenant's signing certificate. That
 * certificate was read, and cached, when the credential was bound to its issuer, so the lookup is a cache hit;
 * it still has no retries and a short timeout. A failure to stage the event is never swallowed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IssuanceCompletionRecorder implements IssuanceCompletionAuditPort {

    private static final Duration PROVIDER_LOOKUP_TIMEOUT = Duration.ofSeconds(2);

    private final AuditTrailPort auditTrail;
    private final TenantSigningConfigService tenantSigningConfigService;
    private final IssuerCertificateService issuerCertificateService;

    @Override
    public Mono<Void> recordCompletion(String issuanceId, Completion completion, String signedCredential) {
        return Mono.defer(() -> {
            Optional<SignatureProof> proof = JwsHeaderFingerprint.of(signedCredential);
            if (proof.isEmpty()) {
                log.warn("issuanceId={} action=auditIssuanceCompleted status=incomplete missing=signingCertificate", issuanceId);
            }
            return providerOf(issuanceId)
                    .map(Optional::of)
                    .defaultIfEmpty(Optional.empty())
                    .flatMap(provider -> auditTrail.stage(IssuanceAuditEvents.completed(
                            issuanceId, provider.orElse(null), completion,
                            proof.map(SignatureProof::algorithm).orElse(null),
                            proof.map(SignatureProof::certificateHash).orElse(null),
                            JwsHeaderFingerprint.fingerprintOf(signedCredential.getBytes(StandardCharsets.UTF_8)))));
        });
    }

    /** The organization of the signing certificate, whether the tenant signs through a QTSP or with its own key. */
    private Mono<DetailedIssuer> detailedIssuerOf(ActiveSigningConfig config) {
        return switch (config.modality()) {
            case QTSP -> issuerCertificateService.resolveRemoteDetailedIssuer(config.qtsp());
            case OWN_KEY -> issuerCertificateService.resolveOwnKeyDetailedIssuer(config.ownKey());
        };
    }

    private Mono<Provider> providerOf(String issuanceId) {
        return tenantSigningConfigService.getActiveSigningConfig()
                .flatMap(this::detailedIssuerOf)
                .timeout(PROVIDER_LOOKUP_TIMEOUT)
                .map(issuer -> new Provider(issuer.organization(), issuer.organizationIdentifier()))
                .filter(Provider::isComplete)
                .switchIfEmpty(Mono.fromRunnable(() -> log.warn(
                        "issuanceId={} action=auditIssuanceCompleted status=incomplete missing=provider", issuanceId)))
                .onErrorResume(error -> {
                    log.warn("issuanceId={} action=auditIssuanceCompleted status=incomplete missing=provider error={}",
                            issuanceId, error.toString());
                    return Mono.empty();
                });
    }
}
