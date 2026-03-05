package es.in2.issuer.backend.backoffice.application.workflow.policies.impl;

import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.entities.CredentialProcedure;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.infrastructure.repository.CredentialProcedureRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Collections;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.LEAR_CREDENTIAL_EMPLOYEE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class BackofficePdpServiceImplTest {

    @Mock
    private PolicyContextFactory policyContextFactory;

    @Mock
    private CredentialProcedureRepository credentialProcedureRepository;

    private BackofficePdpServiceImpl backofficePdp;

    @BeforeEach
    void setUp() {
        // Use a real PolicyEnforcer since it's a stateless component
        PolicyEnforcer policyEnforcer = new PolicyEnforcer();
        backofficePdp = new BackofficePdpServiceImpl(policyContextFactory, policyEnforcer, credentialProcedureRepository);
    }

    private PolicyContext buildContext(String orgId, boolean sysAdmin) {
        return new PolicyContext(
                orgId,
                Collections.singletonList(Power.builder().function("Onboarding").action("Execute").domain(orgId).build()),
                null,
                null,
                LEAR_CREDENTIAL_EMPLOYEE,
                sysAdmin,
                orgId
        );
    }

    private PolicyContext buildContextNoPowers(String orgId, boolean sysAdmin) {
        return new PolicyContext(orgId, Collections.emptyList(), null, null, LEAR_CREDENTIAL_EMPLOYEE, sysAdmin, orgId);
    }

    @Test
    void validateSignCredential_adminOrg_skipsDbLookup() {
        String token = "token";
        String adminOrgId = "admin-org";
        String procedureId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContext(adminOrgId, true);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result).verifyComplete();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateSendReminder_nonAdmin_orgMismatch_denied() {
        String token = "token";
        String userOrgId = "org-123";
        String procedureId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContext(userOrgId, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        CredentialProcedure credentialProcedure = mock(CredentialProcedure.class);
        when(credentialProcedure.getOrganizationIdentifier()).thenReturn("other-org");

        when(credentialProcedureRepository.findById(UUID.fromString(procedureId)))
                .thenReturn(Mono.just(credentialProcedure));

        Mono<Void> result = backofficePdp.validateSendReminder("process", token, procedureId);

        StepVerifier.create(result)
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void validateCommon_noPower_throwsUnauthorizedRoleException() {
        String token = "token";
        String procedureId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContextNoPowers("some-org", false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result)
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateCommon_jwtClaimsParseError_throwsJWTParsingException() {
        String token = "token";
        String procedureId = UUID.randomUUID().toString();

        when(policyContextFactory.fromTokenSimple(eq(token), any()))
                .thenReturn(Mono.error(new JWTParsingException("bad claims")));

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result)
                .expectError(JWTParsingException.class)
                .verify();

        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateCommon_parseTokenThrows_propagatesError() {
        String token = "token";
        String procedureId = UUID.randomUUID().toString();

        when(policyContextFactory.fromTokenSimple(eq(token), any()))
                .thenReturn(Mono.error(new RuntimeException("parse error")));

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result)
                .expectErrorMessage("parse error")
                .verify();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
        verifyNoInteractions(credentialProcedureRepository);
    }

    @Test
    void validateCommon_nonAdmin_repoEmpty_completes() {
        String token = "token";
        String userOrgId = "org-123";
        String procedureId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContext(userOrgId, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        when(credentialProcedureRepository.findById(UUID.fromString(procedureId)))
                .thenReturn(Mono.empty());

        Mono<Void> result = backofficePdp.validateSignCredential("process", token, procedureId);

        StepVerifier.create(result).verifyComplete();

        verify(credentialProcedureRepository).findById(UUID.fromString(procedureId));
    }
}
