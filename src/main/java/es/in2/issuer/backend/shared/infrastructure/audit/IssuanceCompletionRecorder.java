package es.in2.issuer.backend.shared.infrastructure.audit;

import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Completion;
import es.in2.issuer.backend.shared.domain.model.audit.IssuanceAuditEvents.Provider;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.signing.domain.service.IssuerCertificateService;
import es.in2.issuer.backend.signing.domain.util.JwsHeaderFingerprint;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Records the {@code IssuanceCompleted} event of an attestation that is being delivered. The event is staged
 * in the transaction that is already active, so it commits or rolls back with the write that marks the
 * attestation as delivered (DT-002 RQ-01, EC-10): if the outbox insert fails, so does the delivery, and a
 * restart cannot lose the event. The caller opens the transaction.
 *
 * <p>The event is only recorded when it can be complete. The signing certificate and algorithm come from
 * the header of the signed JWS, so a signature without one (a COSE one) is not reported, and the provider is
 * the organization of the tenant's signing certificate. That certificate was read, and cached, when the
 * credential was bound to its issuer, so the lookup is a cache hit; it still has no retries and a short
 * timeout. Only a failed lookup is skipped, with a warning: a failure to stage the event is never swallowed.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IssuanceCompletionRecorder {

    private static final Duration PROVIDER_LOOKUP_TIMEOUT = Duration.ofSeconds(2);

    private final AuditTrailPort auditTrail;
    private final TenantSigningConfigService tenantSigningConfigService;
    private final IssuerCertificateService issuerCertificateService;

    public Mono<Void> recordCompletion(String issuanceId, Completion completion, String signedCredential) {
        return Mono.defer(() -> JwsHeaderFingerprint.of(signedCredential)
                .map(proof -> providerOf(issuanceId)
                        .flatMap(provider -> auditTrail.stage(IssuanceAuditEvents.completed(
                                issuanceId, provider, completion, proof.algorithm(), proof.certificateHash(),
                                JwsHeaderFingerprint.fingerprintOf(signedCredential.getBytes(StandardCharsets.UTF_8))))))
                .orElseGet(Mono::empty));
    }

    private Mono<Provider> providerOf(String issuanceId) {
        return tenantSigningConfigService.getRemoteSignature()
                .flatMap(issuerCertificateService::resolveRemoteDetailedIssuer)
                .timeout(PROVIDER_LOOKUP_TIMEOUT)
                .map(issuer -> new Provider(issuer.organization(), issuer.organizationIdentifier()))
                .filter(Provider::isComplete)
                .onErrorResume(error -> {
                    log.warn("issuanceId={} action=auditIssuanceCompleted status=skipped error={}", issuanceId, error.toString());
                    return Mono.empty();
                });
    }
}
