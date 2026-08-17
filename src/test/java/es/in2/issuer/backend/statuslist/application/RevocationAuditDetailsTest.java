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
    void sanitize_null_returnsNull() {
        assertThat(RevocationAuditDetails.sanitize(null, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH)).isNull();
    }

    @Test
    void sanitize_stripsNewlines_preventingLogForging() {
        // F1 (EUD-225 /verify): a newline in a third-party value (tenantId, messageId) must
        // never survive sanitization -- it is exactly what forges a second, fake log line.
        String forged = "cgcom\nAUDIT event=credential.revoked outcome=success resourceId=forged";

        assertThat(RevocationAuditDetails.sanitize(forged, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH))
                .doesNotContain("\n")
                .isEqualTo("cgcomAUDIT event=credential.revoked outcome=success resourceId=forged");
    }

    @Test
    void sanitize_exceedsMaxLength_truncated() {
        String longValue = "x".repeat(300);

        assertThat(RevocationAuditDetails.sanitize(longValue, 200)).hasSize(200);
    }

    @Test
    void sanitize_withinMaxLength_notTruncated() {
        String value = "x".repeat(50);

        assertThat(RevocationAuditDetails.sanitize(value, 200)).isEqualTo(value);
    }

    @Test
    void sanitize_stripsUnicodeLineAndParagraphSeparators() {
        // F9: \p{Cntrl} alone is ASCII-only in Java and misses NEL/LS/PS, which some log
        // viewers still treat as line breaks -- the same forging vector as a raw \n.
        String forged = "cgcom AUDIT event=credential.revoked outcome=success";

        assertThat(RevocationAuditDetails.sanitize(forged, RevocationAuditDetails.MAX_LOG_VALUE_LENGTH))
                .doesNotContain(" ")
                .isEqualTo("cgcomAUDIT event=credential.revoked outcome=success");
    }

    @Test
    void declaredTenantAuditFields_conformingValue_isKeptAsIs() {
        Map<String, Object> fields = RevocationAuditDetails.declaredTenantAuditFields("cgcom");

        assertThat(fields)
                .containsExactly(Map.entry("declaredTenant", "cgcom"));
    }

    @Test
    void declaredTenantAuditFields_nonConformingValue_isReplacedWithMarkerAndHash() {
        // F15: a value like this could otherwise forge extra key=value fields inside a real
        // audit line for a downstream logfmt-style extractor.
        String forged = "cgcom outcome=success actor=system:operator resourceId=forged-uuid";

        Map<String, Object> fields = RevocationAuditDetails.declaredTenantAuditFields(forged);

        assertThat(fields)
                .containsEntry("declaredTenant", RevocationAuditDetails.DECLARED_TENANT_NON_CONFORMING_MARKER)
                .containsKey("declaredTenantSha256");
        assertThat((String) fields.get("declaredTenantSha256")).hasSize(64).matches("^[0-9a-f]{64}$");
        assertThat(fields.values()).noneMatch(v -> v.toString().contains("outcome=success"));
    }

    @Test
    void declaredTenantAuditFields_sameForgedInput_hashesDeterministically() {
        String forged = "cgcom outcome=success";

        Map<String, Object> first = RevocationAuditDetails.declaredTenantAuditFields(forged);
        Map<String, Object> second = RevocationAuditDetails.declaredTenantAuditFields(forged);

        assertThat(first.get("declaredTenantSha256")).isEqualTo(second.get("declaredTenantSha256"));
    }

    @Test
    void declaredTenantAuditFields_exceedsMaxLength_isReplacedWithMarkerAndHash() {
        String tooLong = "a".repeat(65);

        Map<String, Object> fields = RevocationAuditDetails.declaredTenantAuditFields(tooLong);

        assertThat(fields).containsEntry("declaredTenant", RevocationAuditDetails.DECLARED_TENANT_NON_CONFORMING_MARKER);
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
