package es.in2.issuer.backend.shared.application.workflow.impl;

import es.in2.issuer.backend.shared.domain.service.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.backoffice.application.workflow.policies.BackofficePdpService;
import es.in2.issuer.backend.shared.application.workflow.DeferredCredentialWorkflow;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureInvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.CredentialProcedureNotFoundException;
import es.in2.issuer.backend.shared.domain.model.dto.VerifierOauth2AccessToken;
import es.in2.issuer.backend.shared.domain.model.dto.credential.SimpleIssuer;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.util.factory.IssuerFactory;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import es.in2.issuer.backend.signing.domain.spi.SigningProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.UUID;

import es.in2.issuer.backend.shared.domain.util.factory.GenericCredentialBuilder;
import es.in2.issuer.backend.shared.domain.util.sdjwt.SdJwtPayloadBuilder;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;

import static org.mockito.Mockito.*;
import static es.in2.issuer.backend.shared.domain.util.Constants.JWT_VC_JSON;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_MACHINE;

import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@ExtendWith(MockitoExtension.class)
class CredentialSignerWorkflowImplTest {

    @Mock
    private AccessTokenService accessTokenService;

    @Mock
    private BackofficePdpService backofficePdpService;

    @Mock
    private SigningProvider signingProvider;

    @Mock
    private DeferredCredentialWorkflow deferredCredentialWorkflow;

    @Mock
    private IssuerFactory issuerFactory;

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    @Mock
    private CredentialProcedureService credentialProcedureService;

    @Mock
    private DeferredCredentialMetadataService deferredCredentialMetadataService;

    @Mock
    private IssuerProperties appConfig;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private SimpleIssuer simpleIssuer;

    @Mock
    private VerifierOauth2AccessToken verifierOauth2AccessToken;

    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;

    @Mock
    private GenericCredentialBuilder genericCredentialBuilder;

    @Mock
    private SdJwtPayloadBuilder sdJwtPayloadBuilder;

    @Spy
    @InjectMocks
    CredentialSignerWorkflowImpl credentialSignerWorkflow;

    private final String processId = "process-123";
    private final String procedureId = "d290f1ee-6c54-4b01-90e6-d701748f0851";
    private final String authorizationHeader = "Bearer some-token";
    private final String token = "some-token";
    private final String email = "alice@example.com";
    private final String bindedCredential = "bindedCredential";

    private CredentialProfile buildProfile(String credentialType) {
        return CredentialProfile.builder()
                .credentialConfigurationId(credentialType + "_config")
                .credentialDefinition(CredentialProfile.CredentialDefinition.builder()
                        .type(java.util.List.of("VerifiableCredential", credentialType)).build())
                .build();
    }

    @Test
    void testRetrySignUnsignedCredential_Success_LEARCredentialEmployee() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDataSet()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProfile profile = buildProfile(LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialProfileRegistry.getByCredentialType(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email)))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateCredentialDataSetByProcedureId(procedureId, bindedCredential, JWT_VC_JSON))
                .thenReturn(Mono.empty());
        doReturn(Mono.just("signedCredential"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC_JSON);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any())).thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verify(genericCredentialBuilder).bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email));
        verify(credentialProcedureService)
                .updateCredentialDataSetByProcedureId(procedureId, bindedCredential, JWT_VC_JSON);
        verify(credentialSignerWorkflow).signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC_JSON);
        verify(credentialProcedureService).updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
    }

    @Test
    void testRetrySignUnsignedCredential_ThrowsWhenProcedureNotFound() {
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.empty());

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorSatisfies(throwable -> {
                    assertTrue(throwable instanceof CredentialProcedureNotFoundException);
                    assertEquals(
                            "Credential procedure with ID " + procedureId + " was not found",
                            throwable.getMessage()
                    );
                })
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);

    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnMappingCredential() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDataSet()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProfile profile = buildProfile(LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialProfileRegistry.getByCredentialType(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email)))
                .thenReturn(Mono.error(new RuntimeException("Mapping failed")));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMessage("Mapping failed")
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_DefaultCase_ThrowsIllegalArgument() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialType()).thenReturn("UNKNOWN_TYPE");
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        when(credentialProfileRegistry.getByCredentialType("UNKNOWN_TYPE")).thenReturn(null);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMatches(throwable ->
                        throwable instanceof IllegalArgumentException &&
                                throwable.getMessage().contains("Unsupported credential type: UNKNOWN_TYPE")
                )
                .verify();
    }

    @Test
    void testRetrySignUnsignedCredential_NonLabelCredential_DoesNotSendVc() {
        CredentialProcedure initialProcedure = mock(CredentialProcedure.class);
        when(initialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_EMPLOYEE);
        when(initialProcedure.getCredentialDataSet()).thenReturn("decodedCredential");
        when(initialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProcedure updatedProcedure = mock(CredentialProcedure.class);

        CredentialProfile profile = buildProfile(LEAR_CREDENTIAL_EMPLOYEE);
        when(credentialProfileRegistry.getByCredentialType(LEAR_CREDENTIAL_EMPLOYEE)).thenReturn(profile);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(initialProcedure), Mono.just(updatedProcedure));

        when(genericCredentialBuilder.bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email)))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateCredentialDataSetByProcedureId(procedureId, bindedCredential, JWT_VC_JSON))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedVc"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC_JSON);
        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(updatedProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .verifyComplete();

        // Verify generic credential builder flow
        verify(genericCredentialBuilder).bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email));
        verify(credentialProcedureService)
                .updateCredentialDataSetByProcedureId(procedureId, bindedCredential, JWT_VC_JSON);

        // No VC delivery should happen for non-LABEL credentials
        verifyNoInteractions(deferredCredentialMetadataService);
    }

    @Test
    void testRetrySignUnsignedCredential_ValidationFails() {
        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.error(new RuntimeException("Validation failed")));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMessage("Validation failed")
                .verify();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void testRetrySignUnsignedCredential_StatusNotPendSignature_ThrowsInvalidStatusException() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialStatus()).thenReturn(null);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectError(CredentialProcedureInvalidStatusException.class)
                .verify();

        verify(credentialProcedureRepository).findByProcedureId(UUID.fromString(procedureId));

        verifyNoInteractions(issuerFactory);
    }

    @Test
    void testRetrySignUnsignedCredential_Success_LEARCredentialMachine() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDataSet()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_MACHINE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProfile profile = buildProfile(LEAR_CREDENTIAL_MACHINE);
        when(credentialProfileRegistry.getByCredentialType(LEAR_CREDENTIAL_MACHINE)).thenReturn(profile);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));

        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email)))
                .thenReturn(Mono.just(bindedCredential));
        when(credentialProcedureService.updateCredentialDataSetByProcedureId(procedureId, bindedCredential, JWT_VC_JSON))
                .thenReturn(Mono.empty());

        doReturn(Mono.just("signedCredential"))
                .when(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC_JSON);

        when(credentialProcedureService.updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId))
                .thenReturn(Mono.empty());
        when(credentialProcedureRepository.save(any()))
                .thenReturn(Mono.just(credentialProcedure));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .verifyComplete();

        verify(accessTokenService).getCleanBearerToken(authorizationHeader);
        verify(backofficePdpService).validateSignCredential(processId, token, procedureId);
        verify(accessTokenService).getMandateeEmail(authorizationHeader);
        verify(credentialProcedureRepository, atLeastOnce()).findByProcedureId(UUID.fromString(procedureId));

        verify(genericCredentialBuilder).bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email));
        verify(credentialProcedureService)
                .updateCredentialDataSetByProcedureId(procedureId, bindedCredential, JWT_VC_JSON);
        verify(credentialSignerWorkflow)
                .signAndUpdateCredentialByProcedureId(token, procedureId, JWT_VC_JSON);
        verify(credentialProcedureService)
                .updateCredentialProcedureCredentialStatusToValidByProcedureId(procedureId);
        verify(credentialProcedureRepository).save(any());
    }

    @Test
    void testRetrySignUnsignedCredential_ErrorOnMappingCredential_LEARCredentialMachine() {
        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getCredentialDataSet()).thenReturn("decodedCredential");
        when(credentialProcedure.getCredentialType()).thenReturn(LEAR_CREDENTIAL_MACHINE);
        when(credentialProcedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.PEND_SIGNATURE);

        CredentialProfile profile = buildProfile(LEAR_CREDENTIAL_MACHINE);
        when(credentialProfileRegistry.getByCredentialType(LEAR_CREDENTIAL_MACHINE)).thenReturn(profile);

        when(accessTokenService.getCleanBearerToken(authorizationHeader))
                .thenReturn(Mono.just(token));
        when(backofficePdpService.validateSignCredential(processId, token, procedureId))
                .thenReturn(Mono.empty());
        when(accessTokenService.getMandateeEmail(authorizationHeader))
                .thenReturn(Mono.just(email));
        when(credentialProcedureRepository.findByProcedureId(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));
        when(genericCredentialBuilder.bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email)))
                .thenReturn(Mono.error(new RuntimeException("Machine mapping failed")));

        StepVerifier.create(
                        credentialSignerWorkflow.retrySignUnsignedCredential(processId, authorizationHeader, procedureId)
                )
                .expectErrorMessage("Machine mapping failed")
                .verify();

        verify(genericCredentialBuilder).bindIssuer(eq(profile), eq("decodedCredential"), eq(procedureId), eq(email));
    }

}