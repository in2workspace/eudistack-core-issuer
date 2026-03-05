package es.in2.issuer.backend.shared.domain.util.factory;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.issuer.backend.shared.domain.exception.CredentialTypeUnsupportedException;
import es.in2.issuer.backend.shared.domain.model.dto.CredentialProcedureCreationRequest;
import es.in2.issuer.backend.shared.domain.model.dto.PreSubmittedCredentialDataRequest;
import es.in2.issuer.backend.shared.domain.model.dto.credential.CredentialStatus;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.service.CredentialProcedureService;
import es.in2.issuer.backend.shared.domain.service.DeferredCredentialMetadataService;
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

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

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
                .credentialDecoded("decoded")
                .credentialType(LEAR_CREDENTIAL_EMPLOYEE)
                .subject("subject")
                .validUntil(new Timestamp(System.currentTimeMillis()))
                .signatureMode("sign")
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
                .credentialDecoded("decoded")
                .credentialType(LEAR_CREDENTIAL_MACHINE)
                .subject("machine-subject")
                .validUntil(new Timestamp(System.currentTimeMillis()))
                .signatureMode("sign")
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

    @Test
    void testBindCryptographicCredentialSubjectId_Success() {
        //Arrange
        String processId = "processId";
        String credentialType = "LEARCredentialEmployee";
        String credential = "credential";
        String mandateeId = "mandateeId";
        String result = "result";

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(credentialType)).thenReturn(profile);

        when(genericCredentialBuilder.bindSubjectId(credential, mandateeId))
                .thenReturn(Mono.just(result));

        //Act & Assert
        StepVerifier.create(credentialFactory.bindCryptographicCredentialSubjectId(processId, credentialType, credential, mandateeId))
                .expectNext(result)
                .verifyComplete();

        verify(genericCredentialBuilder).bindSubjectId(credential, mandateeId);
    }

    @Test
    void testBindCryptographicCredentialSubjectId_Failure() {
        //Arrange
        String processId = "processId";
        String credentialType = "UNSUPPORTED_CREDENTIAL";
        String credential = "credential";
        String mandateeId = "mandateeId";

        when(credentialProfileRegistry.getByConfigurationId(credentialType)).thenReturn(null);
        when(credentialProfileRegistry.getByCredentialType(credentialType)).thenReturn(null);

        //Act & Assert
        StepVerifier.create(credentialFactory.bindCryptographicCredentialSubjectId(processId, credentialType, credential, mandateeId))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verify(genericCredentialBuilder, never()).bindSubjectId(anyString(), anyString());
    }

    @Test
    void testBindCryptographicCredentialSubjectId_Machine_Success() {
        // Arrange
        String processId = "processId";
        String decodedCredential = "decodedCredential";
        String subjectDid = "did:key:zDna...";
        String expected = "boundCredential";

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(LEAR_CREDENTIAL_MACHINE)).thenReturn(profile);

        when(genericCredentialBuilder.bindSubjectId(decodedCredential, subjectDid))
                .thenReturn(Mono.just(expected));

        // Act & Assert
        StepVerifier.create(
                        credentialFactory.bindCryptographicCredentialSubjectId(
                                processId,
                                LEAR_CREDENTIAL_MACHINE,
                                decodedCredential,
                                subjectDid
                        )
                )
                .expectNext(expected)
                .verifyComplete();

        verify(genericCredentialBuilder).bindSubjectId(decodedCredential, subjectDid);
    }

    @Test
    void testBindCryptographicCredentialSubjectId_Machine_ErrorPropagates() {
        // Arrange
        String processId = "processId";
        String credentialType = LEAR_CREDENTIAL_MACHINE;
        String decodedCredential = "decodedCredential";
        String subjectDid = "did:key:zDna...";
        RuntimeException error = new RuntimeException("bind error");

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(credentialType)).thenReturn(profile);

        when(genericCredentialBuilder.bindSubjectId(decodedCredential, subjectDid))
                .thenReturn(Mono.error(error));

        // Act & Assert
        StepVerifier.create(
                        credentialFactory.bindCryptographicCredentialSubjectId(
                                processId,
                                credentialType,
                                decodedCredential,
                                subjectDid
                        )
                )
                .expectErrorMatches(t -> t == error)
                .verify();

        verify(genericCredentialBuilder).bindSubjectId(decodedCredential, subjectDid);
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_Success() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String boundCredential = "boundCredential";
        String format = "format";
        String authServerNonce = "nonce";

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        when(genericCredentialBuilder.bindIssuer(profile, decodedCredential, procedureId, ""))
                .thenReturn(Mono.just(boundCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, boundCredential, format))
                .thenReturn(Mono.empty());
        when(deferredCredentialMetadataService.updateDeferredCredentialByAuthServerNonce(authServerNonce, format))
                .thenReturn(Mono.empty());

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, LEAR_CREDENTIAL_EMPLOYEE, format, authServerNonce, ""))
                .verifyComplete();

        verify(genericCredentialBuilder).bindIssuer(profile, decodedCredential, procedureId, "");
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, boundCredential, format);
        verify(deferredCredentialMetadataService).updateDeferredCredentialByAuthServerNonce(authServerNonce, format);
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_UnsupportedCredentialType_Error() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String credentialType = "unsupportedType";
        String format = "format";
        String authServerNonce = "nonce";

        when(credentialProfileRegistry.getByConfigurationId(credentialType)).thenReturn(null);
        when(credentialProfileRegistry.getByCredentialType(credentialType)).thenReturn(null);

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, credentialType, format, authServerNonce, ""))
                .expectError(CredentialTypeUnsupportedException.class)
                .verify();

        verify(genericCredentialBuilder, never()).bindIssuer(any(), any(), any(), any());
        verify(credentialProcedureService, never()).updateDecodedCredentialByProcedureId(any(), any(), any());
        verify(deferredCredentialMetadataService, never()).updateDeferredCredentialMetadataByAuthServerNonce(any());
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_BindIssuer_Error() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String format = "format";
        String authServerNonce = "nonce";

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        when(genericCredentialBuilder.bindIssuer(profile, decodedCredential, procedureId, ""))
                .thenReturn(Mono.error(new RuntimeException("Binding error")));

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, LEAR_CREDENTIAL_EMPLOYEE, format, authServerNonce, ""))
                .expectError(RuntimeException.class)
                .verify();

        verify(genericCredentialBuilder).bindIssuer(profile, decodedCredential, procedureId, "");
        verify(credentialProcedureService, never()).updateDecodedCredentialByProcedureId(any(), any(), any());
        verify(deferredCredentialMetadataService, never()).updateDeferredCredentialMetadataByAuthServerNonce(any());
    }

    @Test
    void mapCredentialBindIssuerAndUpdateDB_UpdateDB_Error() {
        String processId = "processId";
        String procedureId = "procedureId";
        String decodedCredential = "decodedCredential";
        String boundCredential = "boundCredential";
        String format = "format";
        String authServerNonce = "nonce";

        CredentialProfile profile = mock(CredentialProfile.class);
        when(credentialProfileRegistry.getByConfigurationId(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        when(genericCredentialBuilder.bindIssuer(profile, decodedCredential, procedureId, ""))
                .thenReturn(Mono.just(boundCredential));
        when(credentialProcedureService.updateDecodedCredentialByProcedureId(procedureId, boundCredential, format))
                .thenReturn(Mono.error(new RuntimeException("DB Update error")));

        StepVerifier.create(credentialFactory.mapCredentialBindIssuerAndUpdateDB(processId, procedureId, decodedCredential, LEAR_CREDENTIAL_EMPLOYEE, format, authServerNonce, ""))
                .expectError(RuntimeException.class)
                .verify();

        verify(genericCredentialBuilder).bindIssuer(profile, decodedCredential, procedureId, "");
        verify(credentialProcedureService).updateDecodedCredentialByProcedureId(procedureId, boundCredential, format);
        verify(deferredCredentialMetadataService).updateDeferredCredentialByAuthServerNonce(authServerNonce, format);
    }
}
