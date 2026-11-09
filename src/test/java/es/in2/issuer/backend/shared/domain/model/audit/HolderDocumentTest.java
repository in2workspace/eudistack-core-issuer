package es.in2.issuer.backend.shared.domain.model.audit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HolderDocumentTest {

    @Test
    void of_documentNumberAtTheRootOfAnSdJwtDataSet_isTheDocument() {
        String dataSet = "{\"given_name\":\"Jane\",\"document_number\":\"X1234567\"}";

        assertEquals("X1234567", HolderDocument.of(dataSet).orElseThrow());
    }

    @Test
    void of_severalClaims_followsTheOrderDocumentNumberThenAdministrativeNumberThenEmployeeId() {
        String dataSet = "{\"mandatee\":{\"employeeId\":\"E-9\"},\"personal_administrative_number\":\"P-5\"}";

        assertEquals("P-5", HolderDocument.of(dataSet).orElseThrow());
    }

    @Test
    void of_w3cDataSet_findsTheEmployeeIdUnderTheCredentialSubject() {
        String dataSet = "{\"credentialSubject\":{\"mandate\":{\"mandatee\":{\"employeeId\":\"E-9\",\"email\":\"a@b.c\"}}}}";

        assertEquals("E-9", HolderDocument.of(dataSet).orElseThrow());
    }

    @Test
    void of_blankValueIsSkippedInFavourOfTheNextClaim() {
        String dataSet = "{\"document_number\":\" \",\"personal_administrative_number\":\"P-5\"}";

        assertEquals("P-5", HolderDocument.of(dataSet).orElseThrow());
    }

    @Test
    void of_dataSetWithNoneOfTheClaims_hasNoDocument() {
        assertTrue(HolderDocument.of("{\"given_name\":\"Jane\"}").isEmpty());
    }

    @Test
    void of_missingOrMalformedDataSet_hasNoDocumentInsteadOfFailing() {
        assertTrue(HolderDocument.of(null).isEmpty());
        assertTrue(HolderDocument.of(" ").isEmpty());
        assertTrue(HolderDocument.of("not json").isEmpty());
    }

    @Test
    void ofAttestation_fillsTheIdentifierOfTheHolderWithTheDocument() {
        IssuanceAuditEvents.Holder holder =
                IssuanceAuditEvents.Holder.ofAttestation("Jane Doe", "jane@example.com", "{\"document_number\":\"X1\"}");

        assertEquals("X1", holder.identifier());
        assertEquals("Jane Doe", holder.name());
    }
}
