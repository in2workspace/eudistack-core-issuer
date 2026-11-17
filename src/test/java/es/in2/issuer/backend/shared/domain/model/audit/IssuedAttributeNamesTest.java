package es.in2.issuer.backend.shared.domain.model.audit;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IssuedAttributeNamesTest {

    @Test
    void of_w3cCredential_listsTheSubjectClaimsWithoutTheGeneratedSubjectId() {
        // Arrange
        String dataSet = "{\"@context\":[\"x\"],\"id\":\"urn:uuid:1\",\"type\":[\"VerifiableCredential\"],"
                + "\"credentialSubject\":{\"id\":\"urn:uuid:2\",\"mandate\":{\"mandatee\":{\"firstName\":\"Jane\",\"email\":\"j@x.org\"},"
                + "\"power\":[{\"function\":\"Onboarding\",\"action\":[\"Execute\"]}]}},\"validFrom\":\"2026-01-01\"}";

        // Act
        List<String> names = IssuedAttributeNames.of(dataSet);

        // Assert
        assertEquals(List.of("mandate.mandatee.firstName", "mandate.mandatee.email",
                "mandate.power.function", "mandate.power.action"), names);
    }

    @Test
    void of_flatSdJwtCredential_listsTheClaimsWithoutTheEnvelope() {
        // Arrange
        String dataSet = "{\"vct\":\"v\",\"iss\":\"\",\"iat\":1,\"nbf\":1,\"exp\":2,\"mandatee\":{\"firstName\":\"Jane\"},"
                + "\"validFrom\":\"2026-01-01\",\"validUntil\":\"2027-01-01\"}";

        // Act
        List<String> names = IssuedAttributeNames.of(dataSet);

        // Assert
        assertEquals(List.of("mandatee.firstName"), names);
    }

    @Test
    void of_valuesAreNeverPartOfTheNames() {
        // Arrange
        String dataSet = "{\"credentialSubject\":{\"secretValue\":\"do-not-leak\"}}";

        // Act
        List<String> names = IssuedAttributeNames.of(dataSet);

        // Assert
        assertEquals(List.of("secretValue"), names);
    }

    @Test
    void of_blankOrUnparsableDataSet_returnsNoNames() {
        // Arrange & Act & Assert
        assertEquals(List.of(), IssuedAttributeNames.of(null));
        assertEquals(List.of(), IssuedAttributeNames.of(" "));
        assertEquals(List.of(), IssuedAttributeNames.of("{not json"));
    }
}
