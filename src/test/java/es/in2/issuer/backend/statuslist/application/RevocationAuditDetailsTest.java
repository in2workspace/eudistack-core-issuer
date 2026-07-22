package es.in2.issuer.backend.statuslist.application;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RevocationAuditDetailsTest {

    @Test
    void sanitizeReason_null_mapsToNotProvided() {
        assertThat(RevocationAuditDetails.sanitizeReason(null))
                .isEqualTo(RevocationAuditDetails.REASON_NOT_PROVIDED);
    }

    @Test
    void sanitizeReason_blank_mapsToNotProvided() {
        assertThat(RevocationAuditDetails.sanitizeReason("   "))
                .isEqualTo(RevocationAuditDetails.REASON_NOT_PROVIDED);
    }

    @Test
    void sanitizeReason_trimsWhitespace() {
        assertThat(RevocationAuditDetails.sanitizeReason("  Baja del empleado  "))
                .isEqualTo("Baja del empleado");
    }

    @Test
    void sanitizeReason_exceeds280Chars_truncatedTo280() {
        String longReason = "x".repeat(300);

        String sanitized = RevocationAuditDetails.sanitizeReason(longReason);

        assertThat(sanitized).hasSize(RevocationAuditDetails.MAX_REASON_LENGTH);
    }

    @Test
    void sanitizeReason_within280Chars_notTruncated() {
        String reason = "x".repeat(280);

        assertThat(RevocationAuditDetails.sanitizeReason(reason)).hasSize(280);
    }

    @Test
    void sanitizeReason_stripsControlChars() {
        String reason = "Baja" + "" + " del empleado";

        assertThat(RevocationAuditDetails.sanitizeReason(reason)).isEqualTo("Baja del empleado");
    }

    @Test
    void toDetailsMap_includesRequiredFields() {
        Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                "alice@example.com", "VATES-A15456585", "issuance-123", "Baja laboral", "success", null);

        assertThat(details)
                .containsEntry("actor", "alice@example.com")
                .containsEntry("organizationId", "VATES-A15456585")
                .containsEntry("resourceType", "Credential")
                .containsEntry("resourceId", "issuance-123")
                .containsEntry("action", "REVOKE")
                .containsEntry("outcome", "success")
                .containsEntry("reason", "Baja laboral");
    }

    @Test
    void toDetailsMap_failureOutcome_includesErrorType() {
        Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                "alice@example.com", "VATES-A15456585", "issuance-123", null, "failure", "invalid_status");

        assertThat(details).containsEntry("errorType", "invalid_status");
        assertThat(details).containsEntry("reason", RevocationAuditDetails.REASON_NOT_PROVIDED);
    }

    @Test
    void toDetailsMap_successOutcome_omitsErrorTypeKey() {
        Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                "alice@example.com", "VATES-A15456585", "issuance-123", "Baja", "success", null);

        assertThat(details).doesNotContainKey("errorType");
    }

    @Test
    void toDetailsMap_nullOrganizationId_mapsToEmptyString() {
        Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                "alice@example.com", null, "issuance-123", "Baja", "attempted", null);

        assertThat(details).containsEntry("organizationId", "");
    }

    @Test
    void toDetailsMap_nullActor_mapsToUnknown() {
        Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                null, "VATES-A15456585", "issuance-123", "Baja", "attempted", null);

        assertThat(details).containsEntry("actor", "unknown");
    }

    @Test
    void toDetailsMap_neverContainsForbiddenKeys() {
        Map<String, Object> details = RevocationAuditDetails.toDetailsMap(
                "alice@example.com", "VATES-A15456585", "issuance-123", "motivo", "success", null);

        assertThat(details).doesNotContainKeys("email", "subject", "token", "credentialDataSet", "issuance");
    }
}
