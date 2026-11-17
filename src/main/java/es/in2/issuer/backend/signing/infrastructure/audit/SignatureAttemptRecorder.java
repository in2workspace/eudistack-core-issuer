package es.in2.issuer.backend.signing.infrastructure.audit;

import es.in2.issuer.backend.signing.domain.util.SigningFailureReasons;
import es.in2.issuer.backend.signing.domain.model.SigningFailureReason;
import es.in2.issuer.backend.signing.domain.exception.RemoteSignatureUnauthorizedException;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.shared.infrastructure.audit.ExternalFailureClassifier;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignedObject;
import es.in2.issuer.backend.signing.domain.spi.SignatureAuditPort;
import es.in2.issuer.backend.signing.domain.util.JwsHeaderFingerprint;
import es.in2.issuer.backend.shared.domain.service.TenantSigningConfigService;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.Modality;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.concurrent.TimeUnit;

/**
 * Records a {@code SignatureRequested} event around one signing attempt. The event goes in a transaction
 * of its own and best effort: signing happens in the middle of an issuance or a status list update, and a
 * broken audit channel must not fail a signature that was made.
 *
 * <p>A successful signature is only reported when the certificate and algorithm can be read from it, since
 * the catalogue requires them; a signature without a JWS header (a COSE one) is not reported.
 *
 * <p>The modality is the one of the tenant's active configuration (within a signing scope, the one the
 * attempt used). An attempt with no readable configuration has no modality to state, and the catalogue
 * does not allow a guess, so it is not reported; the failure of the operation that needed the signature
 * is reported by that operation.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SignatureAttemptRecorder implements SignatureAuditPort {

    private final AuditTrailPort auditTrail;
    private final TenantSigningConfigService tenantSigningConfigService;

    /**
     * @param resource the object the signature is for, {@code <kind>:<id>}
     * @param signing  the signing attempt; it emits the signed value, a compact JWS for the JADES format
     */
    @Override
    public Mono<String> recordAttempt(String resource, SignedObject signedObject, Mono<String> signing) {
        return Mono.defer(() -> {
            long startedAt = System.nanoTime();
            return signing
                    .flatMap(signed -> stageSuccess(resource, signedObject, signed, elapsedMillis(startedAt))
                            .thenReturn(signed))
                    .onErrorResume(error -> stageFailure(resource, signedObject, error, elapsedMillis(startedAt))
                            .then(Mono.<String>error(error)));
        });
    }

    private Mono<Void> stageSuccess(String resource, SignedObject signedObject, String signed, long durationMs) {
        return JwsHeaderFingerprint.of(signed)
                .map(proof -> modalityOf().flatMap(modality -> auditTrail.stageBestEffort(
                        SigningAuditEvents.signed(resource, signedObject, modality, proof, durationMs))))
                .orElseGet(Mono::empty);
    }

    private Mono<Void> stageFailure(String resource, SignedObject signedObject, Throwable error, long durationMs) {
        return modalityOf().flatMap(modality -> auditTrail.stageBestEffort(
                SigningAuditEvents.failed(resource, signedObject, modality, reasonOf(error), durationMs)));
    }

    private Mono<Modality> modalityOf() {
        return tenantSigningConfigService.getActiveSigningConfig()
                .map(config -> Modality.of(config.modality()))
                .onErrorResume(error -> {
                    log.warn("action=auditSignatureRequested status=skipped reason=modalityUnknown error={}", error.toString());
                    return Mono.empty();
                });
    }

    private static String reasonOf(Throwable error) {
        if (SigningFailureReasons.of(error) == SigningFailureReason.NO_CONFIGURATION) {
            return "NoActiveConfiguration";
        }
        if (causedBy(error, RemoteSignatureUnauthorizedException.class)) {
            return "CredentialsRejected";
        }
        return switch (ExternalFailureClassifier.reasonOf(error)) {
            case ExternalFailureClassifier.AUTHENTICATION_REJECTED -> "CredentialsRejected";
            case ExternalFailureClassifier.INVALID_RESPONSE -> "InvalidSignatureResponse";
            default -> "ProviderUnavailable";
        };
    }

    private static boolean causedBy(Throwable error, Class<? extends Throwable> type) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (type.isInstance(current)) {
                return true;
            }
        }
        return false;
    }

    private static long elapsedMillis(long startedAt) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
    }
}
