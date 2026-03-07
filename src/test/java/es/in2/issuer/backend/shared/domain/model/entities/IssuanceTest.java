package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IssuanceTest {

    @Test
    void testIssuance() {
        UUID issuanceId = UUID.randomUUID();
        String credentialFormat = "testFormat";
        String credentialDataSet = "testDataSet";
        CredentialStatusEnum credentialStatusEnum = CredentialStatusEnum.VALID;
        String organizationIdentifier = "testOrganizationIdentifier";
        String credentialType = "LEARCredentialEmployee";
        Timestamp validUntil = new Timestamp(System.currentTimeMillis() + 1000);
        String email = "test@example.com";
        String delivery = "email";

        Issuance issuance = Issuance.builder()
                .issuanceId(issuanceId)
                .credentialFormat(credentialFormat)
                .credentialDataSet(credentialDataSet)
                .credentialStatus(credentialStatusEnum)
                .organizationIdentifier(organizationIdentifier)
                .credentialType(credentialType)
                .validUntil(validUntil)
                .email(email)
                .delivery(delivery)
                .build();

        assertEquals(issuanceId, issuance.getIssuanceId());
        assertEquals(credentialFormat, issuance.getCredentialFormat());
        assertEquals(credentialDataSet, issuance.getCredentialDataSet());
        assertEquals(credentialStatusEnum, issuance.getCredentialStatus());
        assertEquals(organizationIdentifier, issuance.getOrganizationIdentifier());
        assertEquals(credentialType, issuance.getCredentialType());
        assertEquals(validUntil, issuance.getValidUntil());
        assertEquals(email, issuance.getEmail());
        assertEquals(delivery, issuance.getDelivery());
    }

    @Test
    void testSettersAndGetters() {
        Issuance issuance = new Issuance();
        UUID issuanceId = UUID.randomUUID();
        String credentialFormat = "format";
        String credentialDataSet = "dataSet";
        CredentialStatusEnum credentialStatusEnum = CredentialStatusEnum.VALID;
        String organizationIdentifier = "orgId";
        String credentialType = "LEARCredentialEmployee";
        Timestamp validUntil = new Timestamp(System.currentTimeMillis() + 1000);
        String email = "test@example.com";

        issuance.setIssuanceId(issuanceId);
        issuance.setCredentialFormat(credentialFormat);
        issuance.setCredentialDataSet(credentialDataSet);
        issuance.setCredentialStatus(credentialStatusEnum);
        issuance.setOrganizationIdentifier(organizationIdentifier);
        issuance.setCredentialType(credentialType);
        issuance.setValidUntil(validUntil);
        issuance.setEmail(email);

        assertEquals(issuanceId, issuance.getIssuanceId());
        assertEquals(credentialFormat, issuance.getCredentialFormat());
        assertEquals(credentialDataSet, issuance.getCredentialDataSet());
        assertEquals(credentialStatusEnum, issuance.getCredentialStatus());
        assertEquals(organizationIdentifier, issuance.getOrganizationIdentifier());
        assertEquals(credentialType, issuance.getCredentialType());
        assertEquals(validUntil, issuance.getValidUntil());
        assertEquals(email, issuance.getEmail());
    }
}
