package es.in2.issuer.backend.signing.infrastructure.audit;

import es.in2.issuer.backend.signing.domain.exception.RemoteSignatureUnauthorizedException;
import es.in2.issuer.backend.shared.domain.model.audit.AuditEntry;
import es.in2.issuer.backend.shared.domain.spi.AuditTrailPort;
import es.in2.issuer.backend.shared.infrastructure.audit.ExternalFailureClassifier;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents;
import es.in2.issuer.backend.signing.domain.audit.SigningAuditEvents.SignedObject;
import es.in2.issuer.backend.signing.domain.exception.NoActiveSigningConfigurationException;
import es.in2.issuer.backend.signing.domain.util.JwsHeaderFingerprint;
import lombok.RequiredArgsConstructor;
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
 */
@Component
@RequiredArgsConstructor
public class SignatureAttemptRecorder {

    private final AuditTrailPort auditTrail;

    /**
     * @param resource the object the signature is for, {@code <kind>:<id>}
     * @param signing  the signing attempt; it emits the signed value, a compact JWS for the JADES format
     */
    public Mono<String> record(String resource, SignedObject signedObject, Mono<String> signing) {
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
                .map(proof -> auditTrail.stageBestEffort(SigningAuditEvents.signed(resource, signedObject, proof, durationMs)))
                .orElseGet(Mono::empty);
    }

    private Mono<Void> stageFailure(String resource, SignedObject signedObject, Throwable error, long durationMs) {
        AuditEntry entry = SigningAuditEvents.failed(resource, signedObject, reasonOf(error), durationMs);
        return auditTrail.stageBestEffort(entry);
    }

    private static String reasonOf(Throwable error) {
        if (error instanceof NoActiveSigningConfigurationException) {
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
