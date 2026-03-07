package es.in2.issuer.backend.shared.domain.model.dto;

import org.junit.jupiter.api.Test;

import static es.in2.issuer.backend.shared.domain.util.Constants.LABEL_CREDENTIAL;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;

import java.sql.Timestamp;

import static org.assertj.core.api.Assertions.assertThat;

class IssuanceCreationRequestTest {

    @Test
    void builderShouldCreateRecordWithAllFields() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        IssuanceCreationRequest request = IssuanceCreationRequest.builder()
                .issuanceId("proc-123")
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
                .returns("proc-123", IssuanceCreationRequest::issuanceId)
                .returns("org-456", IssuanceCreationRequest::organizationIdentifier)
                .returns("decoded-credential", IssuanceCreationRequest::credentialDataSet)
                .returns(LEAR_CREDENTIAL_EMPLOYEE, IssuanceCreationRequest::credentialType)
                .returns("jwt_vc", IssuanceCreationRequest::credentialFormat)
                .returns("did:example:subject", IssuanceCreationRequest::subject)
                .returns(validUntil, IssuanceCreationRequest::validUntil)
                .returns("roger@example.com", IssuanceCreationRequest::email)
                .returns("sync", IssuanceCreationRequest::delivery);
    }

    @Test
    void equalsAndHashCodeShouldWorkForSameValues() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        IssuanceCreationRequest a = IssuanceCreationRequest.builder()
                .issuanceId("proc-1")
                .organizationIdentifier("org-1")
                .credentialDataSet("cred")
                .credentialType(LABEL_CREDENTIAL)
                .credentialFormat("jwt_vc")
                .subject("subj")
                .validUntil(validUntil)
                .email("a@b.com")
                .delivery("async")
                .build();

        IssuanceCreationRequest b = IssuanceCreationRequest.builder()
                .issuanceId("proc-1")
                .organizationIdentifier("org-1")
                .credentialDataSet("cred")
                .credentialType(LABEL_CREDENTIAL)
                .credentialFormat("jwt_vc")
                .subject("subj")
                .validUntil(validUntil)
                .email("a@b.com")
                .delivery("async")
                .build();

        IssuanceCreationRequest c = IssuanceCreationRequest.builder()
                .issuanceId("proc-2")
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
        IssuanceCreationRequest request = IssuanceCreationRequest.builder()
                .issuanceId("proc-123")
                .organizationIdentifier("org-456")
                .email("roger@example.com")
                .build();

        // Act
        String text = request.toString();

        // Assert
        assertThat(text)
                .contains("IssuanceCreationRequest")
                .contains("issuanceId=proc-123")
                .contains("organizationIdentifier=org-456")
                .contains("email=roger@example.com");
    }

    @Test
    void builderShouldAllowNullsWhenNotProvided() {
        // Arrange
        IssuanceCreationRequest request = IssuanceCreationRequest.builder()
                .issuanceId("proc-123")
                .build();

        // Assert
        assertThat(request)
                .returns("proc-123", IssuanceCreationRequest::issuanceId)
                .returns(null, IssuanceCreationRequest::organizationIdentifier)
                .returns(null, IssuanceCreationRequest::credentialDataSet)
                .returns(null, IssuanceCreationRequest::credentialType)
                .returns(null, IssuanceCreationRequest::credentialFormat)
                .returns(null, IssuanceCreationRequest::subject)
                .returns(null, IssuanceCreationRequest::validUntil)
                .returns(null, IssuanceCreationRequest::email)
                .returns(null, IssuanceCreationRequest::delivery);
    }

    @Test
    void timestampIsMutableAndRecordDoesNotDefensivelyCopyIt() {
        // Arrange
        Timestamp validUntil = Timestamp.valueOf("2030-01-01 10:15:30");

        IssuanceCreationRequest request = IssuanceCreationRequest.builder()
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
