package es.in2.issuer.backend.dome.infrastructure.observability;

import es.in2.issuer.backend.dome.domain.model.keymigration.KmsAlias;
import es.in2.issuer.backend.dome.domain.model.keymigration.LegacyKeyId;
import es.in2.issuer.backend.dome.domain.model.keymigration.MigrationStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class KeyMigrationAuditLogger {

    public static final Marker AUDIT_MARKER = MarkerFactory.getMarker("AUDIT_KEY_MIGRATION");

    public void logPlanAOk(LegacyKeyId keyId, KmsAlias alias) {
        log.info(AUDIT_MARKER, "event=PLAN_A_OK legacyKeyId={} alias={}",
                keyId.value(), alias.value());
    }

    public void logPocResult(LegacyKeyId keyId, MigrationStatus result) {
        log.info(AUDIT_MARKER, "event=POC_RESULT legacyKeyId={} result={}",
                keyId.value(), result);
    }

    public void logFailure(LegacyKeyId keyId, String errorClass) {
        log.error(AUDIT_MARKER, "event=FAILURE legacyKeyId={} errorClass={}",
                keyId.value(), errorClass);
    }

    public void logEvent(String event, String safeDetail) {
        log.info(AUDIT_MARKER, "event={} detail={}", event, safeDetail);
    }
}

