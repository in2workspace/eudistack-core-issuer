package es.in2.issuer.backend.statuslist.application.policies.impl;

import es.in2.issuer.backend.backoffice.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;

import static es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum.VALID;
import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StatusListPdpServiceImplTest {

    @Mock
    private PolicyContextFactory policyContextFactory;

    private StatusListPdpServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new StatusListPdpServiceImpl(policyContextFactory);
    }

    private PolicyContext buildContext(String orgId, boolean sysAdmin) {
        return new PolicyContext(
                orgId,
                Collections.singletonList(Power.builder().function("Onboarding").action("Execute").domain(orgId).build()),
                null,
                LEAR_CREDENTIAL_EMPLOYEE,
                sysAdmin,
                orgId
        );
    }

    private PolicyContext buildContextNoPowers(String orgId, boolean sysAdmin) {
        return new PolicyContext(orgId, Collections.emptyList(), null, LEAR_CREDENTIAL_EMPLOYEE, sysAdmin, orgId);
    }

    @Test
    void validateRevokeCredential_shouldComplete_whenValidStatus_roleLear_andSameOrganization() {
        // Arrange
        String processId = "p-1";
        String token = "token";
        String procedureOrg = "ORG_1";
        String userOrg = "ORG_1";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);
        when(procedure.getOrganizationIdentifier()).thenReturn(procedureOrg);

        PolicyContext ctx = buildContext(userOrg, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential(processId, token, procedure))
                .verifyComplete();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
    }

    @Test
    void validateRevokeCredential_shouldComplete_whenUserIsSysAdmin_evenIfOrganizationDiffers() {
        // Arrange
        String processId = "p-2";
        String token = "token";
        String procedureOrg = "ORG_2";
        String adminOrg = "ADMIN";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);
        when(procedure.getOrganizationIdentifier()).thenReturn(procedureOrg);

        PolicyContext ctx = buildContext(adminOrg, true);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential(processId, token, procedure))
                .verifyComplete();
    }

    @Test
    void validateRevokeCredential_shouldErrorInvalidStatus_whenStatusIsNotValid() {
        // Arrange
        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-3", "token", procedure))
                .expectError(InvalidStatusException.class)
                .verify();

        verifyNoInteractions(policyContextFactory);
    }

    @Test
    void validateRevokeCredential_shouldErrorUnauthorizedRole_whenNoPower() {
        // Arrange
        String token = "token";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);

        PolicyContext ctx = buildContextNoPowers("ORG_1", false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-4", token, procedure))
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
    }

    @Test
    void validateRevokeCredential_shouldErrorJwtParsingException_whenClaimsCannotBeParsed() {
        // Arrange
        String token = "token";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);

        when(policyContextFactory.fromTokenSimple(eq(token), any()))
                .thenReturn(Mono.error(new JWTParsingException("boom")));

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-5", token, procedure))
                .expectError(JWTParsingException.class)
                .verify();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
    }

    @Test
    void validateRevokeCredential_shouldErrorUnauthorizedRole_whenOrganizationDiffersAndNotSysAdmin() {
        // Arrange
        String token = "token";
        String procedureOrg = "ORG_A";
        String userOrg = "ORG_B";

        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);
        when(procedure.getOrganizationIdentifier()).thenReturn(procedureOrg);

        PolicyContext ctx = buildContext(userOrg, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredential("p-6", token, procedure))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void validateRevokeCredentialSystem_shouldComplete_whenValidStatus() {
        // Arrange
        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(VALID);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredentialSystem("p-7", procedure))
                .verifyComplete();

        verifyNoInteractions(policyContextFactory);
    }

    @Test
    void validateRevokeCredentialSystem_shouldErrorInvalidStatus_whenNotValid() {
        // Arrange
        CredentialProcedure procedure = mock(CredentialProcedure.class);
        when(procedure.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        // Act + Assert
        StepVerifier.create(service.validateRevokeCredentialSystem("p-8", procedure))
                .expectError(InvalidStatusException.class)
                .verify();

        verifyNoInteractions(policyContextFactory);
    }
}
