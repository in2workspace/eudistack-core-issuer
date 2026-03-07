package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IssuanceListTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        IssuanceSummary procedureBasicInfo = new IssuanceSummary(
                UUID.randomUUID(),
                "John Doe",
                "LEAR_CREDENTIAL_EMPLOYEE",
                "In Progress",
                Instant.parse("2023-01-01T12:00:00Z"),
                "or"
                );
        IssuanceList.IssuanceEntry issuance = new IssuanceList.IssuanceEntry(procedureBasicInfo);
        List<IssuanceList.IssuanceEntry> expectedIssuanceList = List.of(issuance);

        // Act
        IssuanceList issuances = new IssuanceList(expectedIssuanceList);

        // Assert
        assertEquals(expectedIssuanceList, issuances.issuances());
    }

    @Test
    void testSetters() {
        // Arrange
        IssuanceSummary procedureBasicInfo = new IssuanceSummary(
                UUID.randomUUID(),
                "Jane Doe",
                "LEAR_CREDENTIAL_EMPLOYEE",
                "Completed",
                Instant.parse("2024-01-01T12:00:00Z"),
                "org"
        );
        IssuanceList.IssuanceEntry issuance = new IssuanceList.IssuanceEntry(procedureBasicInfo);
        List<IssuanceList.IssuanceEntry> newIssuanceList = List.of(issuance);

        // Act
        IssuanceList issuances = IssuanceList.builder()
                .issuances(newIssuanceList)
                .build();

        // Assert
        assertEquals(newIssuanceList, issuances.issuances());
    }

    @Test
    void lombokGeneratedMethodsTest() {
        // Arrange
        IssuanceSummary procedureBasicInfo = new IssuanceSummary(
                UUID.randomUUID(),
                "John Doe",
                "LEAR_CREDENTIAL_EMPLOYEE",
                "In Progress",
                Instant.parse("2023-01-01T12:00:00Z"),
                "org"
        );
        IssuanceList.IssuanceEntry issuance = new IssuanceList.IssuanceEntry(procedureBasicInfo);
        List<IssuanceList.IssuanceEntry> expectedIssuanceList = List.of(issuance);

        IssuanceList issuances1 = new IssuanceList(expectedIssuanceList);
        IssuanceList issuances2 = new IssuanceList(expectedIssuanceList);

        // Assert
        assertEquals(issuances1, issuances2);
        assertEquals(issuances1.hashCode(), issuances2.hashCode());
    }
}