package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.model.query.PageCursor;
import es.in2.issuer.backend.shared.domain.model.query.PagePosition;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.REVOKED;
import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/** EUD-255 contract: the shape of the listing parameters (API-10 step 4). */
class IssuanceListParametersTest {

    @Test
    void noParameters_isTheFirstPageOfEverything() {
        IssuanceQuery query = IssuanceListParameters.toQuery(null, null, null, null, null);

        assertThat(query).isEqualTo(IssuanceQuery.firstPage());
    }

    @Test
    void everyParameter_isRead() {
        PageCursor cursor = new PageCursor(new PagePosition(Instant.parse("2026-10-01T09:00:00Z"), UUID.randomUUID()), "d");

        IssuanceQuery query = IssuanceListParameters.toQuery(
                "VALID, REVOKED", "doctor.sd.1", "sandbox", "10", cursor.encode());

        assertThat(query.lifeCycleStatuses()).containsExactlyInAnyOrder(VALID, REVOKED);
        assertThat(query.credentialConfigurationId()).isEqualTo("doctor.sd.1");
        assertThat(query.tenant()).isEqualTo("sandbox");
        assertThat(query.limit()).isEqualTo(10);
        assertThat(query.cursor()).isEqualTo(cursor);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ACTIVE", "valid", "VALID,", ",VALID", ""})
    void anUnknownOrEmptyState_isAViolation(String states) {
        assertThat(fields(states, null, null, null, null)).containsExactly("life_cycle_status");
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "201", "-5", "ten", "1.5", ""})
    void aLimitThatIsNotFrom1To200_isAViolation(String limit) {
        assertThat(fields(null, null, null, limit, null)).containsExactly("limit");
    }

    @Test
    void blankOrTooLongTexts_areViolations() {
        assertThat(fields(null, " ", null, null, null)).containsExactly("credential_configuration_id");
        assertThat(fields(null, "x".repeat(101), null, null, null)).containsExactly("credential_configuration_id");
        assertThat(fields(null, null, "", null, null)).containsExactly("tenant");
        assertThat(fields(null, null, "t".repeat(64), null, null)).containsExactly("tenant");
    }

    @Test
    void aCursorThatIsNotOurs_isAViolation() {
        assertThat(fields(null, null, null, null, "garbage")).containsExactly("cursor");
    }

    @Test
    void everyFieldWithAProblem_isReported_withoutItsValue() {
        String secret = "28/12345";

        InvalidQueryException error = catchThrowableOfType(InvalidQueryException.class,
                () -> IssuanceListParameters.toQuery(secret, secret, null, secret, secret));

        assertThat(error.violations()).extracting(InvalidQueryException.Violation::field)
                .containsExactly("life_cycle_status", "limit", "cursor");
        assertThat(error.violations().toString()).doesNotContain(secret);
        assertThat(error.getMessage()).doesNotContain(secret);
    }

    private static java.util.List<String> fields(String states, String entry, String tenant, String limit, String cursor) {
        InvalidQueryException error = catchThrowableOfType(InvalidQueryException.class,
                () -> IssuanceListParameters.toQuery(states, entry, tenant, limit, cursor));
        assertThat(error).isNotNull();
        return error.violations().stream().map(InvalidQueryException.Violation::field).toList();
    }
}
