package es.in2.issuer.backend.dome.infrastructure.observability;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.stereotype.Component;

/**
 * Structured audit logger for DOME key migration events.
 * <p>
 * All log statements are tagged with {@link #AUDIT_MARKER} so that downstream
 * log aggregation (e.g. CloudWatch Logs Insights, Loki) can filter and alert
 * on migration audit events independently of the application log stream.
 * </p>
 * <p>
 * NFR-07 / allowlist: methods only accept {@code String} or domain types already
 * guaranteed not to contain raw key material. {@code EncryptedKeyEnvelope} and
 * {@code byte[]} are intentionally excluded from every parameter list.
 * </p>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class KeyMigrationAuditLogger {

    public static final Marker AUDIT_MARKER = MarkerFactory.getMarker("AUDIT_KEY_MIGRATION");

    /**
     * Records a successful Plan-A import.
     *
     * @param keyId the legacy key identifier (value-object, never raw bytes)
     * @param alias the KMS alias under which the key was imported
     */
    public void logPlanAOk(LegacyKeyId keyId, KmsAlias alias) {
        log.info(AUDIT_MARKER, "event=PLAN_A_OK legacyKeyId={} alias={}",
                keyId.value(), alias.value());
    }

    /**
     * Records the outcome of a Proof-of-Concept signing test.
     *
     * @param keyId  the legacy key identifier
     * @param result the migration status resulting from the PoC
     */
    public void logPocResult(LegacyKeyId keyId, MigrationStatus result) {
        log.info(AUDIT_MARKER, "event=POC_RESULT legacyKeyId={} result={}",
                keyId.value(), result);
    }

    /**
     * Records a terminal failure for a key migration step.
     * <p>
     * Only the exception class name is logged — never the message, which could
     * contain key material captured during an error path.
     * </p>
     *
     * @param keyId      the legacy key identifier
     * @param errorClass the simple class name of the thrown exception
     */
    public void logFailure(LegacyKeyId keyId, String errorClass) {
        log.error(AUDIT_MARKER, "event=FAILURE legacyKeyId={} errorClass={}",
                keyId.value(), errorClass);
    }

    /**
     * Emits a generic structured audit event with the AUDIT_KEY_MIGRATION marker.
     * Used for fire-and-forget CloudWatch audit emission.
     *
     * @param event      the event name (e.g. "PLAN_B_REISSUE", "POC_RESULT")
     * @param safeDetail a pre-sanitised detail string — caller must ensure it
     *                   contains no ciphertext, private keys, or key material
     */
    public void logEvent(String event, String safeDetail) {
        log.info(AUDIT_MARKER, "event={} detail={}", event, safeDetail);
    }
}

