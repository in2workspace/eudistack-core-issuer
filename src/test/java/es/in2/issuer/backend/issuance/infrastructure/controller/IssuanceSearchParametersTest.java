package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException;
import es.in2.issuer.backend.shared.domain.exception.InvalidQueryException.Violation;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.model.query.IssuanceQuery;
import es.in2.issuer.backend.shared.domain.model.query.SearchIdentifierCriterion;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/** EUD-255 contract {@code SearchRequest}, AC-07, EC-05 and ES-04: the shape of the body of the search. */
class IssuanceSearchParametersTest {

    @Test
    void aSearchByName_withTheFiltersOfTheListing() {
        IssuanceQuery query = IssuanceSearchParameters.toQuery("""
                {"subject": "garcia", "life_cycle_status": ["VALID", "REVOKED"],
                 "credential_configuration_id": "doctor.sd.1", "limit": 10}""");

        assertThat(query.subject()).isEqualTo("garcia");
        assertThat(query.lifeCycleStatuses()).containsExactlyInAnyOrder(CredentialStatusEnum.VALID, CredentialStatusEnum.REVOKED);
        assertThat(query.credentialConfigurationId()).isEqualTo("doctor.sd.1");
        assertThat(query.limit()).isEqualTo(10);
        assertThat(query.tenant()).isNull();
        assertThat(query.cursor()).isNull();
    }

    @Test
    void theDefaultPageSize_isTheListingOne() {
        assertThat(IssuanceSearchParameters.toQuery("{\"subject\": \"garcia\"}").limit())
                .isEqualTo(IssuanceQuery.DEFAULT_LIMIT);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "[]", "\"garcia\"", "42", "null", "{\"subject\": \"garcia\"", "subject=garcia"})
    void aBodyThatIsNotAJsonObject_isNamedAsTheBody(String body) {
        assertThat(violations(body)).extracting(Violation::field).containsExactly("body");
    }

    @Test
    void noBody_isNamedAsTheBody() {
        assertThat(violations(null)).extracting(Violation::field).containsExactly("body");
    }

    /** ES-04: the parser's message quotes the body; none of it reaches the violation or the exception. */
    @Test
    void aBodyThatIsNotJson_isNotQuotedAnywhere() {
        InvalidQueryException error = catchThrowableOfType(InvalidQueryException.class,
                () -> IssuanceSearchParameters.toQuery("{\"subject\": María García"));

        assertThat(error.getMessage()).doesNotContain("María");
        assertThat(error.getCause()).isNull();
        assertThat(error.violations()).allSatisfy(violation -> assertThat(violation.message()).doesNotContain("María"));
    }

    @Test
    void aDuplicatedField_isNotAJsonObjectOfTheSearch() {
        assertThat(violations("{\"subject\": \"garcia\", \"subject\": \"lopez\"}"))
                .extracting(Violation::field).containsExactly("body");
    }

    @Test
    void aFieldTheContractDoesNotDefine_isNamed() {
        assertThat(violations("{\"subject\": \"garcia\", \"name\": \"garcia\"}"))
                .extracting(Violation::field).containsExactly("name");
    }

    @Test
    void aFieldWhoseNameIsNotOne_isNamedAsTheBody_withoutRepeatingIt() {
        List<Violation> violations = violations("{\"subject\": \"garcia\", \"María García\": 1}");

        assertThat(violations).extracting(Violation::field).containsExactly("body");
        assertThat(violations.getFirst().message()).doesNotContain("María");
    }

    @Test
    void theSubjectAndTheIdentifier_atOnce_areRefused() {
        assertThat(violations("{\"subject\": \"garcia\", \"identifier_type\": \"dni\", \"identifier\": \"12345678Z\"}"))
                .extracting(Violation::field).containsExactly("subject");
    }

    @Test
    void neitherTheSubjectNorTheIdentifier_isRefused() {
        assertThat(violations("{\"life_cycle_status\": [\"VALID\"]}"))
                .extracting(Violation::field).containsExactly("subject");
    }

    @Test
    void halfAnIdentifier_namesTheOtherHalf() {
        assertThat(violations("{\"identifier_type\": \"dni\"}")).extracting(Violation::field).containsExactly("identifier");
        assertThat(violations("{\"identifier\": \"12345678Z\"}")).extracting(Violation::field).containsExactly("identifier_type");
    }

    /** AC-05: the search by identifier, as received, still to be fingerprinted by the use case. */
    @Test
    void aSearchByIdentifier_withTheFiltersOfTheListing() {
        IssuanceQuery query = IssuanceSearchParameters.toQuery("""
                {"identifier_type": "colegiado", "identifier": "28 / 12345", "life_cycle_status": ["VALID"],
                 "tenant": "sandbox"}""");

        assertThat(query.identifier()).isEqualTo(SearchIdentifierCriterion.searched("colegiado", "28 / 12345"));
        assertThat(query.subject()).isNull();
        assertThat(query.lifeCycleStatuses()).containsExactly(CredentialStatusEnum.VALID);
        assertThat(query.tenant()).isEqualTo("sandbox");
    }

    @Test
    void aSearchByName_hasNoIdentifier() {
        assertThat(IssuanceSearchParameters.toQuery("{\"subject\": \"garcia\"}").identifier()).isNull();
    }

    @Test
    void anIdentifierTooLong_isNamedWithoutItsValue() {
        String value = "X".repeat(IssuanceSearchParameters.IDENTIFIER_MAX_LENGTH + 1);
        List<Violation> violations = violations("{\"identifier_type\": \"dni\", \"identifier\": \"" + value + "\"}");

        assertThat(violations).extracting(Violation::field).containsExactly("identifier");
        assertThat(violations.getFirst().message()).doesNotContain(value);
    }

    /** AC-07, EC-05: at least three characters not counting spaces. */
    @ParameterizedTest
    @ValueSource(strings = {"ma", "g a", "  ab  ", " ", ""})
    void aSubjectShorterThanThreeCharacters_isRefused(String subject) {
        assertThat(violations("{\"subject\": \"" + subject + "\"}")).extracting(Violation::field).containsExactly("subject");
    }

    @Test
    void aSubjectOfThreeCharactersWithSpaces_isAccepted() {
        assertThat(IssuanceSearchParameters.toQuery("{\"subject\": \" g a r \"}").subject()).isEqualTo(" g a r ");
    }

    @Test
    void aSubjectLongerThanTheContract_isRefused() {
        assertThat(violations("{\"subject\": \"" + "a".repeat(101) + "\"}"))
                .extracting(Violation::field).containsExactly("subject");
    }

    @Test
    void everyFieldWithAProblem_isNamed_once() {
        List<Violation> violations = violations("""
                {"subject": 7, "life_cycle_status": "VALID", "credential_configuration_id": "",
                 "tenant": 1, "limit": 500, "cursor": "nope"}""");

        assertThat(violations).extracting(Violation::field).containsExactly(
                "subject", "life_cycle_status", "credential_configuration_id", "tenant", "limit", "cursor");
    }

    @Test
    void aStateThatIsNotOne_isRefused() {
        assertThat(violations("{\"subject\": \"garcia\", \"life_cycle_status\": [\"VALID\", \"ACTIVE\"]}"))
                .extracting(Violation::field).containsExactly("life_cycle_status");
        assertThat(violations("{\"subject\": \"garcia\", \"life_cycle_status\": []}"))
                .extracting(Violation::field).containsExactly("life_cycle_status");
    }

    @Test
    void aLimitThatIsNotAnIntegerInRange_isRefused() {
        assertThat(violations("{\"subject\": \"garcia\", \"limit\": 1.5}")).extracting(Violation::field).containsExactly("limit");
        assertThat(violations("{\"subject\": \"garcia\", \"limit\": \"10\"}")).extracting(Violation::field).containsExactly("limit");
        assertThat(violations("{\"subject\": \"garcia\", \"limit\": 0}")).extracting(Violation::field).containsExactly("limit");
    }

    @Test
    void noViolation_repeatsTheValueSearched() {
        List<Violation> violations = violations("""
                {"subject": "María García", "identifier_type": "colegiado", "identifier": "28/12345", "limit": -1}""");

        assertThat(violations).isNotEmpty().allSatisfy(violation -> assertThat(violation.message())
                .doesNotContain("María").doesNotContain("28/12345").doesNotContain("colegiado"));
    }

    private static List<Violation> violations(String body) {
        InvalidQueryException error = catchThrowableOfType(InvalidQueryException.class,
                () -> IssuanceSearchParameters.toQuery(body));
        assertThat(error).as("the body should have been refused").isNotNull();
        return error.violations();
    }

    @Test
    void aValidSearch_throwsNothing() {
        assertThatCode(() -> IssuanceSearchParameters.toQuery("{\"subject\": \"gar\"}")).doesNotThrowAnyException();
    }
}
