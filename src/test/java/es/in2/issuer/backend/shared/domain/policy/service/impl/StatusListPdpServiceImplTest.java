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

    // ---------------------------------------------------------------- EUD-271

    @Test
    void validateRevokeScope_otherOrganization_readsAsNotFound_whateverTheStatus() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getOrganizationIdentifier()).thenReturn("ORG_2");
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(buildContext("ORG_1", false)));

        StepVerifier.create(service.validateRevokeScope("p", "token", issuance))
                .expectError(es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException.class)
                .verify();
    }

    @Test
    void validateRevokeScope_sameOrganization_doesNotLookAtTheStatus() {
        Issuance issuance = mock(Issuance.class);
        when(issuance.getOrganizationIdentifier()).thenReturn("ORG_1");
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(buildContext("ORG_1", false)));

        StepVerifier.create(service.validateRevokeScope("p", "token", issuance)).verifyComplete();

        verify(issuance, never()).getCredentialStatus();
    }

    @Test
    void validateRevokeScope_withoutThePower_isInsufficientPermission_notNotFound() {
        Issuance issuance = mock(Issuance.class);
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(buildContextNoPowers("ORG_1", false)));

        StepVerifier.create(service.validateRevokeScope("p", "token", issuance))
                .expectError(es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void validateRevokePermission_decidesWithoutAProcess() {
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(buildContextNoPowers("ORG_1", false)));

        StepVerifier.create(service.validateRevokePermission("p", "token"))
                .expectError(es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void validateRevokePermission_withThePower_completes() {
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(buildContext("ORG_1", false)));

        StepVerifier.create(service.validateRevokePermission("p", "token")).verifyComplete();
    }

    private PolicyContext sysAdminOn(String tenant) {
        return new PolicyContext("ORG_1", Collections.emptyList(), null, null, "learcredential.employee.w3c.4",
                true, false, tenant, tenant, null);
    }

    @Test
    void validateRevokeScope_sysAdminOnPlatformTenant_isReadOnly() {
        Issuance issuance = mock(Issuance.class);
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(sysAdminOn("platform")));

        StepVerifier.create(service.validateRevokeScope("p", "token", issuance))
                .expectError(es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void validateRevokePermission_sysAdminOnPlatformTenant_isReadOnly() {
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(sysAdminOn("platform")));

        StepVerifier.create(service.validateRevokePermission("p", "token"))
                .expectError(es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void validateRevokeScope_sysAdminOnAnotherTenant_canRevoke() {
        Issuance issuance = mock(Issuance.class);
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(sysAdminOn("sandbox")));

        StepVerifier.create(service.validateRevokeScope("p", "token", issuance)).verifyComplete();
    }

    @Test
    void validateRevokePermission_tokenWithoutOrganization_isInvalidToken() {
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.just(buildContext(null, false)));

        StepVerifier.create(service.validateRevokePermission("p", "token"))
                .expectError(es.in2.issuer.backend.shared.domain.exception.InvalidTokenException.class)
                .verify();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(classes = {
            es.in2.issuer.backend.shared.domain.exception.JWTClaimMissingException.class,
            es.in2.issuer.backend.shared.domain.exception.JWTParsingException.class,
            es.in2.issuer.backend.shared.domain.exception.InvalidCredentialFormatException.class})
    void validateRevokePermission_unreadableToken_isInvalidToken(Class<? extends RuntimeException> failure) throws Exception {
        RuntimeException error = failure.getConstructor(String.class).newInstance("broken");
        when(policyContextFactory.fromTokenSimple(eq("token"), any())).thenReturn(Mono.error(error));

        StepVerifier.create(service.validateRevokePermission("p", "token"))
                .expectError(es.in2.issuer.backend.shared.domain.exception.InvalidTokenException.class)
                .verify();
    }
}
