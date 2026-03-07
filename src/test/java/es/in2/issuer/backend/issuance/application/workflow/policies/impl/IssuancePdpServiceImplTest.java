package es.in2.issuer.backend.issuance.application.workflow.policies.impl;

import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.UnauthorizedRoleException;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.infrastructure.repository.IssuanceRepository;
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
class IssuancePdpServiceImplTest {

    @Mock
    private PolicyContextFactory policyContextFactory;

    @Mock
    private IssuanceRepository issuanceRepository;

    @Mock
    private AuditService auditService;

    private IssuancePdpServiceImpl issuancePdp;

    @BeforeEach
    void setUp() {
        // Use a real PolicyEnforcer since it's a stateless component
        PolicyEnforcer policyEnforcer = new PolicyEnforcer();
        issuancePdp = new IssuancePdpServiceImpl(policyContextFactory, policyEnforcer, issuanceRepository, auditService);
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
        String issuanceId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContext(adminOrgId, true);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdp.validateSignCredential("process", token, issuanceId);

        StepVerifier.create(result).verifyComplete();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
        verifyNoInteractions(issuanceRepository);
    }

    @Test
    void validateSignCredential_nonAdmin_orgMismatch_denied() {
        String token = "token";
        String userOrgId = "org-123";
        String issuanceId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContext(userOrgId, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        Issuance issuance = mock(Issuance.class);
        when(issuance.getOrganizationIdentifier()).thenReturn("other-org");

        when(issuanceRepository.findById(UUID.fromString(issuanceId)))
                .thenReturn(Mono.just(issuance));

        Mono<Void> result = issuancePdp.validateSignCredential("process", token, issuanceId);

        StepVerifier.create(result)
                .expectError(UnauthorizedRoleException.class)
                .verify();
    }

    @Test
    void validateCommon_noPower_throwsUnauthorizedRoleException() {
        String token = "token";
        String issuanceId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContextNoPowers("some-org", false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        Mono<Void> result = issuancePdp.validateSignCredential("process", token, issuanceId);

        StepVerifier.create(result)
                .expectError(UnauthorizedRoleException.class)
                .verify();

        verifyNoInteractions(issuanceRepository);
    }

    @Test
    void validateCommon_jwtClaimsParseError_throwsJWTParsingException() {
        String token = "token";
        String issuanceId = UUID.randomUUID().toString();

        when(policyContextFactory.fromTokenSimple(eq(token), any()))
                .thenReturn(Mono.error(new JWTParsingException("bad claims")));

        Mono<Void> result = issuancePdp.validateSignCredential("process", token, issuanceId);

        StepVerifier.create(result)
                .expectError(JWTParsingException.class)
                .verify();

        verifyNoInteractions(issuanceRepository);
    }

    @Test
    void validateCommon_parseTokenThrows_propagatesError() {
        String token = "token";
        String issuanceId = UUID.randomUUID().toString();

        when(policyContextFactory.fromTokenSimple(eq(token), any()))
                .thenReturn(Mono.error(new RuntimeException("parse error")));

        Mono<Void> result = issuancePdp.validateSignCredential("process", token, issuanceId);

        StepVerifier.create(result)
                .expectErrorMessage("parse error")
                .verify();

        verify(policyContextFactory).fromTokenSimple(eq(token), any());
        verifyNoInteractions(issuanceRepository);
    }

    @Test
    void validateCommon_nonAdmin_repoEmpty_completes() {
        String token = "token";
        String userOrgId = "org-123";
        String issuanceId = UUID.randomUUID().toString();

        PolicyContext ctx = buildContext(userOrgId, false);
        when(policyContextFactory.fromTokenSimple(eq(token), any())).thenReturn(Mono.just(ctx));

        when(issuanceRepository.findById(UUID.fromString(issuanceId)))
                .thenReturn(Mono.empty());

        Mono<Void> result = issuancePdp.validateSignCredential("process", token, issuanceId);

        StepVerifier.create(result).verifyComplete();

        verify(issuanceRepository).findById(UUID.fromString(issuanceId));
    }
}
