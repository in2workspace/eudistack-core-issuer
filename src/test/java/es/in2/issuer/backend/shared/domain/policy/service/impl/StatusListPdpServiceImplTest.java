package es.in2.issuer.backend.shared.domain.policy.service.impl;

import es.in2.issuer.backend.issuance.domain.exception.InvalidStatusException;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
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
                null,
                "learcredential.employee.w3c.4",
                sysAdmin,
                false,
                orgId,
                orgId
        , null);
    }

    private PolicyContext buildContextNoPowers(String orgId, boolean sysAdmin) {
        return new PolicyContext(orgId, Collections.emptyList(), null, null, "learcredential.employee.w3c.4", sysAdmin, false, orgId, orgId, null);
    }

    @Test
    void validateRevokeCredential_shouldComplete_whenValidStatus_roleLear_andSameOrganization() {
        String processId = "p-1";
        String token = "token";
        String issuanceOrg = "ORG_1";
        String userOrg = "ORG_1";

        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);
        when(issuance.getOrganizationIdentifier()).thenReturn(issuanceOrg);

        PolicyContext ctx = buildContext(userOrg, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        StepVerifier.create(service.validateRevokeCredential(processId, token, issuance))
                .verifyComplete();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
    }

    @Test
    void validateRevokeCredential_shouldComplete_whenUserIsSysAdmin_evenIfOrganizationDiffers() {
        String processId = "p-2";
        String token = "token";
        String issuanceOrg = "ORG_2";
        String adminOrg = "ADMIN";

        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);
        when(issuance.getOrganizationIdentifier()).thenReturn(issuanceOrg);

        PolicyContext ctx = buildContext(adminOrg, true);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        StepVerifier.create(service.validateRevokeCredential(processId, token, issuance))
                .verifyComplete();
    }

    @Test
    void validateRevokeCredential_shouldErrorInvalidStatus_whenStatusIsNotValid() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        StepVerifier.create(service.validateRevokeCredential("p-3", "token", issuance))
                .expectError(InvalidStatusException.class)
                .verify();

        verifyNoInteractions(policyContextFactory);
    }

    @Test
    void validateRevokeCredential_shouldErrorUnauthorizedRole_whenNoPower() {
        String token = "token";

        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);

        PolicyContext ctx = buildContextNoPowers("ORG_1", false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        StepVerifier.create(service.validateRevokeCredential("p-4", token, issuance))
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
    }

    @Test
    void validateRevokeCredential_shouldErrorJwtParsingException_whenClaimsCannotBeParsed() {
        String token = "token";

        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);

        when(policyContextFactory.fromTokenSimple(eq(token), any()))
                .thenReturn(Mono.error(new JWTParsingException("boom")));

        StepVerifier.create(service.validateRevokeCredential("p-5", token, issuance))
                .expectError(JWTParsingException.class)
                .verify();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
    }

    @Test
    void validateRevokeCredential_shouldErrorUnauthorizedRole_whenOrganizationDiffersAndNotSysAdmin() {
        String token = "token";
        String issuanceOrg = "ORG_A";
        String userOrg = "ORG_B";

        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);
        when(issuance.getOrganizationIdentifier()).thenReturn(issuanceOrg);

        PolicyContext ctx = buildContext(userOrg, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        StepVerifier.create(service.validateRevokeCredential("p-6", token, issuance))
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void validateRevokeCredentialSystem_shouldComplete_whenValidStatus() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(VALID);

        StepVerifier.create(service.validateRevokeCredentialSystem("p-7", issuance))
                .verifyComplete();

        verifyNoInteractions(policyContextFactory);
    }

    @Test
    void validateRevokeCredentialSystem_shouldErrorInvalidStatus_whenNotValid() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getCredentialStatus()).thenReturn(CredentialStatusEnum.REVOKED);

        StepVerifier.create(service.validateRevokeCredentialSystem("p-8", issuance))
                .expectError(InvalidStatusException.class)
                .verify();

        verifyNoInteractions(policyContextFactory);
    }
}
