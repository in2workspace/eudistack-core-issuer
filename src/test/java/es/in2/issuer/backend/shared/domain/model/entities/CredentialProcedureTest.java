package es.in2.issuer.backend.shared.domain.model.entities;

import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialProcedureTest {

    @Test
    void testCredentialProcedure() {
        UUID procedureId = UUID.randomUUID();
        String credentialFormat = "testFormat";
        String credentialDataSet = "testDataSet";
        CredentialStatusEnum credentialStatusEnum = CredentialStatusEnum.VALID;
        String organizationIdentifier = "testOrganizationIdentifier";
        String credentialType = "LEARCredentialEmployee";
        Timestamp validUntil = new Timestamp(System.currentTimeMillis() + 1000);
        String email = "test@example.com";
        String delivery = "email";

        CredentialProcedure credentialProcedure = CredentialProcedure.builder()
                .procedureId(procedureId)
                .credentialFormat(credentialFormat)
                .credentialDataSet(credentialDataSet)
                .credentialStatus(credentialStatusEnum)
                .organizationIdentifier(organizationIdentifier)
                .credentialType(credentialType)
                .validUntil(validUntil)
                .email(email)
                .delivery(delivery)
                .build();

        assertEquals(procedureId, credentialProcedure.getProcedureId());
        assertEquals(credentialFormat, credentialProcedure.getCredentialFormat());
        assertEquals(credentialDataSet, credentialProcedure.getCredentialDataSet());
        assertEquals(credentialStatusEnum, credentialProcedure.getCredentialStatus());
        assertEquals(organizationIdentifier, credentialProcedure.getOrganizationIdentifier());
        assertEquals(credentialType, credentialProcedure.getCredentialType());
        assertEquals(validUntil, credentialProcedure.getValidUntil());
        assertEquals(email, credentialProcedure.getEmail());
        assertEquals(delivery, credentialProcedure.getDelivery());
    }

    @Test
    void testSettersAndGetters() {
        CredentialProcedure credentialProcedure = new CredentialProcedure();
        UUID procedureId = UUID.randomUUID();
        String credentialFormat = "format";
        String credentialDataSet = "dataSet";
        CredentialStatusEnum credentialStatusEnum = CredentialStatusEnum.VALID;
        String organizationIdentifier = "orgId";
        String credentialType = "LEARCredentialEmployee";
        Timestamp validUntil = new Timestamp(System.currentTimeMillis() + 1000);
        String email = "test@example.com";

        credentialProcedure.setProcedureId(procedureId);
        credentialProcedure.setCredentialFormat(credentialFormat);
        credentialProcedure.setCredentialDataSet(credentialDataSet);
        credentialProcedure.setCredentialStatus(credentialStatusEnum);
        credentialProcedure.setOrganizationIdentifier(organizationIdentifier);
        credentialProcedure.setCredentialType(credentialType);
        credentialProcedure.setValidUntil(validUntil);
        credentialProcedure.setEmail(email);

        assertEquals(procedureId, credentialProcedure.getProcedureId());
        assertEquals(credentialFormat, credentialProcedure.getCredentialFormat());
        assertEquals(credentialDataSet, credentialProcedure.getCredentialDataSet());
        assertEquals(credentialStatusEnum, credentialProcedure.getCredentialStatus());
        assertEquals(organizationIdentifier, credentialProcedure.getOrganizationIdentifier());
        assertEquals(credentialType, credentialProcedure.getCredentialType());
        assertEquals(validUntil, credentialProcedure.getValidUntil());
        assertEquals(email, credentialProcedure.getEmail());
    }
}
