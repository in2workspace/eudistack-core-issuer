package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.sql.Timestamp;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialFactoryTest {

    @Mock
    private GenericCredentialBuilder genericCredentialBuilder;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @InjectMocks
    private CredentialFactory credentialFactory;

    @Test
    void testMapCredentialIntoACredentialProcedureRequest_LEAREmployee_Success() {
        //Arrange
        String processId = "processId";
        String procedureId = "procedureId";
        String email = "test@example.com";
        JsonNode jsonNode = mock(JsonNode.class);

        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("https://example.com/status/1")
                .type("StatusList2021Entry")
                .statusPurpose("revocation")
                .statusListIndex("12345")
                .statusListCredential("https://example.com/credentials/status/1")
                .build();

        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId(LEAR_CREDENTIAL_EMPLOYEE)
                .payload(jsonNode)
                .build();

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        CredentialProcedureCreationRequest expectedResponse = CredentialProcedureCreationRequest.builder()
                .procedureId(procedureId)
                .organizationIdentifier("org123")
                .credentialDataSet("decoded")
                .credentialType(LEAR_CREDENTIAL_EMPLOYEE)
                .subject("subject")
                .validUntil(new Timestamp(System.currentTimeMillis()))
                .email(email)
                .build();

        when(genericCredentialBuilder.buildCredential(profile, procedureId, jsonNode, credentialStatus, email))
                .thenReturn(Mono.just(expectedResponse));

        //Act & Assert
        StepVerifier.create(credentialFactory.mapCredentialIntoACredentialProcedureRequest(
                        processId, procedureId, preSubmittedCredentialDataRequest, credentialStatus, email))
                .expectNext(expectedResponse)
                .verifyComplete();

        verify(genericCredentialBuilder).buildCredential(profile, procedureId, jsonNode, credentialStatus, email);
    }

    @Test
    void testMapCredentialIntoACredentialProcedureRequest_LEARMachine_Success() {
        //Arrange
        String processId = "processId";
        String procedureId = "procedureId";
        String email = "test@example.com";
        JsonNode jsonNode = mock(JsonNode.class);

        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("https://example.com/status/3")
                .type("StatusList2021Entry")
                .statusPurpose("revocation")
                .statusListIndex("11111")
                .statusListCredential("https://example.com/credentials/status/3")
                .build();

        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId(LEAR_CREDENTIAL_MACHINE)
                .payload(jsonNode)
                .build();

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(LEAR_CREDENTIAL_MACHINE)).thenReturn(profile);

        CredentialProcedureCreationRequest expectedResponse = CredentialProcedureCreationRequest.builder()
                .procedureId(procedureId)
                .organizationIdentifier("org789")
                .credentialDataSet("decoded")
                .credentialType(LEAR_CREDENTIAL_MACHINE)
                .subject("machine-subject")
                .validUntil(new Timestamp(System.currentTimeMillis()))
                .email(email)
                .build();

        when(genericCredentialBuilder.buildCredential(profile, procedureId, jsonNode, credentialStatus, email))
                .thenReturn(Mono.just(expectedResponse));

        //Act & Assert
        StepVerifier.create(credentialFactory.mapCredentialIntoACredentialProcedureRequest(
                        processId, procedureId, preSubmittedCredentialDataRequest, credentialStatus, email))
                .expectNext(expectedResponse)
                .verifyComplete();

        verify(genericCredentialBuilder).buildCredential(profile, procedureId, jsonNode, credentialStatus, email);
    }

    @Test
    void testMapCredentialIntoACredentialProcedureRequest_UnsupportedCredential_Failure() {
        //Arrange
        String processId = "processId";
        String procedureId = "procedureId";
        String email = "test@example.com";

        CredentialStatus credentialStatus = CredentialStatus.builder()
                .id("https://example.com/status/4")
                .type("StatusList2021Entry")
                .statusPurpose("revocation")
                .statusListIndex("99999")
                .statusListCredential("https://example.com/credentials/status/4")
                .build();

        PreSubmittedCredentialDataRequest preSubmittedCredentialDataRequest = PreSubmittedCredentialDataRequest.builder()
                .credentialConfigurationId("UNSUPPORTED_CREDENTIAL")
                .payload(mock(JsonNode.class))
                .build();

        when(credentialProfileRegistry.getByConfigurationId("UNSUPPORTED_CREDENTIAL")).thenReturn(null);
        when(credentialProfileRegistry.getByCredentialType("UNSUPPORTED_CREDENTIAL")).thenReturn(null);

        //Act & Assert
        StepVerifier.create(credentialFactory.mapCredentialIntoACredentialProcedureRequest(
                        processId, procedureId, preSubmittedCredentialDataRequest, credentialStatus, email))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verify(genericCredentialBuilder, never()).buildCredential(any(), any(), any(), any(), any());
    }
}
