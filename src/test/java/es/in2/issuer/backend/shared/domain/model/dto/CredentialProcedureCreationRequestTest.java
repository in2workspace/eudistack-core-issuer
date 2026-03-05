package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;

import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialProcedureCreationRequestTest {

    @Test
    void builderShouldCreateRecordWithAllFields() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .organizationIdentifier("org-456")
                .credentialDataSet("decoded-credential")
                .credentialType(LEAR_CREDENTIAL_EMPLOYEE)
                .credentialFormat("jwt_vc")
                .subject("did:example:subject")
                .validUntil(validUntil)
                .email("roger@example.com")
                .delivery("sync")
                .build();

        // Assert
        assertThat(request)
                .returns("proc-123", CredentialProcedureCreationRequest::procedureId)
                .returns("org-456", CredentialProcedureCreationRequest::organizationIdentifier)
                .returns("decoded-credential", CredentialProcedureCreationRequest::credentialDataSet)
                .returns(LEAR_CREDENTIAL_EMPLOYEE, CredentialProcedureCreationRequest::credentialType)
                .returns("jwt_vc", CredentialProcedureCreationRequest::credentialFormat)
                .returns("did:example:subject", CredentialProcedureCreationRequest::subject)
                .returns(validUntil, CredentialProcedureCreationRequest::validUntil)
                .returns("roger@example.com", CredentialProcedureCreationRequest::email)
                .returns("sync", CredentialProcedureCreationRequest::delivery);
    }

    @Test
    void equalsAndHashCodeShouldWorkForSameValues() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        CredentialProcedureCreationRequest a = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-1")
                .organizationIdentifier("org-1")
                .credentialDataSet("cred")
                .credentialType(LABEL_CREDENTIAL)
                .credentialFormat("jwt_vc")
                .subject("subj")
                .validUntil(validUntil)
                .email("a@b.com")
                .delivery("async")
                .build();

        CredentialProcedureCreationRequest b = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-1")
                .organizationIdentifier("org-1")
                .credentialDataSet("cred")
                .credentialType(LABEL_CREDENTIAL)
                .credentialFormat("jwt_vc")
                .subject("subj")
                .validUntil(validUntil)
                .email("a@b.com")
                .delivery("async")
                .build();

        CredentialProcedureCreationRequest c = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-2")
                .organizationIdentifier("org-1")
                .credentialDataSet("cred")
                .credentialType(LABEL_CREDENTIAL)
                .credentialFormat("jwt_vc")
                .subject("subj")
                .validUntil(validUntil)
                .email("a@b.com")
                .delivery("async")
                .build();

        // Assert
        assertThat(a)
                .isEqualTo(b)
                .hasSameHashCodeAs(b)
                .isNotEqualTo(c)
                .isNotEqualTo(null)
                .isNotEqualTo("not-a-request");
    }

    @Test
    void toStringShouldContainClassNameAndSomeFields() {
        // Arrange
        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .organizationIdentifier("org-456")
                .email("roger@example.com")
                .build();

        // Act
        String text = request.toString();

        // Assert
        assertThat(text)
                .contains("CredentialProcedureCreationRequest")
                .contains("procedureId=proc-123")
                .contains("organizationIdentifier=org-456")
                .contains("email=roger@example.com");
    }

    @Test
    void builderShouldAllowNullsWhenNotProvided() {
        // Arrange
        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .procedureId("proc-123")
                .build();

        // Assert
        assertThat(request)
                .returns("proc-123", CredentialProcedureCreationRequest::procedureId)
                .returns(null, CredentialProcedureCreationRequest::organizationIdentifier)
                .returns(null, CredentialProcedureCreationRequest::credentialDataSet)
                .returns(null, CredentialProcedureCreationRequest::credentialType)
                .returns(null, CredentialProcedureCreationRequest::credentialFormat)
                .returns(null, CredentialProcedureCreationRequest::subject)
                .returns(null, CredentialProcedureCreationRequest::validUntil)
                .returns(null, CredentialProcedureCreationRequest::email)
                .returns(null, CredentialProcedureCreationRequest::delivery);
    }

    @Test
    void timestampIsMutableAndRecordDoesNotDefensivelyCopyIt() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        CredentialProcedureCreationRequest request = CredentialProcedureCreationRequest.builder()
                .validUntil(validUntil)
                .build();

        // Act
        validUntil.setTime(Timestamp.valueOf("2040-01-01 00:00:00").getTime());

        // Assert
        assertThat(request.validUntil())
                .isSameAs(validUntil)
                .satisfies(ts -> assertThat(ts.toString()).startsWith("2040-01-01"));

    }
}
