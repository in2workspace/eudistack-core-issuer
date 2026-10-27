package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException;
import es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException.Reason;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.Scope;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.CallerResolver;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.FileAuthorizationMatrixProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.QUERY;
import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.REVOKE;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * EUD-272 / EUD-253: every action decided by the caller's powers and the organization stored with
 * the resource, with the bundled matrix. Each action has a negative case without the power and one
 * from another tenant.
 */
class PowerAuthorizationServiceImplTest {

    private static final String TENANT = "sandbox";
    private static final String OTHER_TENANT = "kpmg";
    private static final String ORG = "VATES-SUR";
    private static final String OTHER_ORG = "VATES-NORTE";
    private static final String LABEL_TYPE = "gx:LabelCredential";
    private static final String EMPLOYEE_TYPE = "learcredential.employee.w3c.4";

    private static final Power PLATFORM_ADMIN = power("organization", "EUDISTACK", "System", "Administration");
    private static final Power TENANT_ADMIN = power("organization", TENANT, "Onboarding", "Execute");
    private static final Power ORG_ADMIN = power("domain", TENANT, "Onboarding", "Execute");
    private static final Power CERTIFY = power("domain", TENANT, "Certification", "Attest");

    private final ObjectMapper objectMapper = new ObjectMapper();
    private CallerResolver callerResolver;
    private TenantCredentialProfileService tenantCredentialProfileService;
    private AuditService auditService;
    private PowerAuthorizationServiceImpl service;

    @BeforeEach
    void setUp() {
        callerResolver = mock(CallerResolver.class);
        tenantCredentialProfileService = mock(TenantCredentialProfileService.class);
        auditService = mock(AuditService.class);
        when(tenantCredentialProfileService.isProfileAllowed(anyString())).thenReturn(Mono.just(true));
        service = new PowerAuthorizationServiceImpl(new FileAuthorizationMatrixProvider(""), callerResolver,
                tenantCredentialProfileService, auditService, objectMapper);
    }

    // --- helpers ---

    private static Power power(String type, String domain, String function, String action) {
        return new Power(List.of(action), domain, function, type);
    }

    private static Caller caller(String org, String tokenTenant, Power... powers) {
        return new Caller(org, List.of(powers), tokenTenant, "learcredential.machine.w3c.3", "sub-" + org, "jti");
    }

    private <T> Mono<T> inTenant(Mono<T> mono, String tenant) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    private Mono<?> revoke(Caller caller, String resourceOrg) {
        return inTenant(service.authorize(REVOKE, caller, resourceOrg, "issuance-1"), TENANT);
    }

    private Mono<?> issue(Caller caller, String credentialType, String organization, JsonNode payload) {
        when(callerResolver.fromSecurityContext()).thenReturn(Mono.just(caller));
        return inTenant(service.authorizeIssuance("process-1", "config-id", credentialType, organization, payload), TENANT);
    }

    private JsonNode payloadGranting(Power... powers) {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.putObject("mandator").put("organizationIdentifier", OTHER_ORG);
        ArrayNode array = payload.putArray("power");
        for (Power p : powers) {
            array.add(objectMapper.valueToTree(p));
        }
        return payload;
    }

    private static void expectReason(Mono<?> mono, Reason reason) {
        StepVerifier.create(mono)
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(LearIssuancePolicyException.class)
                        .extracting(ex -> ((LearIssuancePolicyException) ex).getReason())
                        .isEqualTo(reason))
                .verify();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> lastDenyDetails(String expectedReason) {
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService, atLeastOnce()).auditFailure(eq("authorization.deny"), any(), eq(expectedReason), details.capture());
        return details.getValue();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> lastPermitDetails() {
        ArgumentCaptor<Map<String, Object>> details = ArgumentCaptor.forClass(Map.class);
        verify(auditService, atLeastOnce()).auditSuccess(eq("authorization.permit"), any(), eq("action"), any(), details.capture());
        return details.getValue();
    }

    // --- recognition (FR-03, §2) ---

    @Nested
    class Recognition {

        @Test
        void recognizesEachUserTypeByItsPowerAlone() {
            assertThat(userType(caller(ORG, TENANT, PLATFORM_ADMIN))).isEqualTo(RecognizedCaller.PLATFORM_ADMIN);
            assertThat(userType(caller(ORG, TENANT, TENANT_ADMIN))).isEqualTo(RecognizedCaller.TENANT_ADMIN);
            assertThat(userType(caller(ORG, TENANT, ORG_ADMIN))).isEqualTo(RecognizedCaller.ORGANIZATION_ADMIN);
            assertThat(userType(caller(ORG, TENANT, CERTIFY))).isEqualTo(RecognizedCaller.USER);
            assertThat(userType(caller(ORG, TENANT))).isEqualTo(RecognizedCaller.USER);
        }

        @Test
        void platformAdminActsAsTenantAdminAndIsASecurityActor() {
            StepVerifier.create(inTenant(service.recognize(caller(ORG, TENANT, PLATFORM_ADMIN)), TENANT))
                    .assertNext(r -> {
                        assertThat(r.actsAs()).isEqualTo(RecognizedCaller.TENANT_ADMIN);
                        assertThat(r.securityAction()).isTrue();
                        assertThat(r.readOnly()).isFalse();
                    })
                    .verifyComplete();
        }

        @Test
        void powerTypeIsComparedInLowercaseOnly() {
            assertThat(userType(caller(ORG, TENANT, power("Domain", TENANT, "Onboarding", "Execute"))))
                    .isEqualTo(RecognizedCaller.USER);
            assertThat(userType(caller(ORG, TENANT, power("Organization", TENANT, "Onboarding", "Execute"))))
                    .isEqualTo(RecognizedCaller.USER);
        }

        private String userType(Caller caller) {
            return inTenant(service.recognize(caller), TENANT).map(RecognizedCaller::userType).block();
        }
    }

    // --- R1: revoke ---

    @Nested
    class Revoke {

        @Test
        void organizationAdminRevokesItsOwnOrganization() {
            StepVerifier.create(revoke(caller(ORG, TENANT, ORG_ADMIN), ORG)).expectNextCount(1).verifyComplete();
        }

        /** Jira AC: a system with domain · tenant · Onboarding · Execute, another organization → issuance_not_found + trace. */
        @Test
        void organizationAdminRevokingAnotherOrganization_failsAsNotFound_andTracesTheReason() {
            StepVerifier.create(revoke(caller(ORG, TENANT, ORG_ADMIN), OTHER_ORG))
                    .expectError(IssuanceNotFoundException.class)
                    .verify();

            Map<String, Object> details = lastDenyDetails("resource_out_of_scope");
            assertThat(details).containsEntry("action", REVOKE)
                    .containsEntry("userType", RecognizedCaller.ORGANIZATION_ADMIN)
                    .containsEntry("resourceOrganization", OTHER_ORG)
                    .containsEntry("callerOrganization", ORG);
        }

        @Test
        void tenantAdminRevokesAnyOrganizationOfTheTenant() {
            StepVerifier.create(revoke(caller(ORG, TENANT, TENANT_ADMIN), OTHER_ORG))
                    .assertNext(d -> assertThat(((es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision) d).scope())
                            .isEqualTo(Scope.ANY_ORGANIZATION))
                    .verifyComplete();
        }

        @Test
        void platformAdminInsideATenant_isPermittedAsItsAdministrator_withSecurityTrace() {
            StepVerifier.create(revoke(caller(ORG, TENANT, PLATFORM_ADMIN), OTHER_ORG)).expectNextCount(1).verifyComplete();

            assertThat(lastPermitDetails()).containsEntry("securityAction", true)
                    .containsEntry("actsAs", RecognizedCaller.TENANT_ADMIN);
        }

        @Test
        void platformAdminFromThePlatformTenant_cannotRevoke() {
            Caller platformAdmin = caller(ORG, "platform", PLATFORM_ADMIN);
            expectReason(inTenant(service.authorize(REVOKE, platformAdmin, OTHER_ORG, "issuance-1"), "platform"),
                    Reason.PLATFORM_TENANT_READ_ONLY);
        }

        @Test
        void withoutPower_isDenied() {
            expectReason(revoke(caller(ORG, TENANT), ORG), Reason.OPERATOR_LACKS_ONBOARDING);
        }

        @Test
        void withThePowerOfAnotherTenant_isDenied() {
            expectReason(revoke(caller(ORG, TENANT, power("domain", OTHER_TENANT, "Onboarding", "Execute")), ORG),
                    Reason.OPERATOR_LACKS_ONBOARDING);
        }

        @Test
        void withATokenOfAnotherTenant_isDenied_evenForThePlatformAdmin() {
            StepVerifier.create(revoke(caller(ORG, OTHER_TENANT, ORG_ADMIN), ORG))
                    .expectError(TenantMismatchException.class).verify();
            StepVerifier.create(revoke(caller(ORG, OTHER_TENANT, PLATFORM_ADMIN), ORG))
                    .expectError(TenantMismatchException.class).verify();
            lastDenyDetails("tenant_mismatch");
        }

        @Test
        void withoutTenantHeader_failsClosed() {
            StepVerifier.create(service.authorize(REVOKE, caller(ORG, TENANT, TENANT_ADMIN), ORG, "issuance-1"))
                    .expectError(TenantMismatchException.class).verify();
        }

        /** AC-08: a system and a person with the same powers get the same decision. */
        @Test
        void personAndSystemWithTheSamePowers_getTheSameDecision() {
            Caller system = new Caller(ORG, List.of(ORG_ADMIN), TENANT, "learcredential.machine.w3c.3", "m", "j");
            Caller person = new Caller(ORG, List.of(ORG_ADMIN), TENANT, "learcredential.employee.w3c.4", "p", "j");

            StepVerifier.create(revoke(system, OTHER_ORG)).expectError(IssuanceNotFoundException.class).verify();
            StepVerifier.create(revoke(person, OTHER_ORG)).expectError(IssuanceNotFoundException.class).verify();
            StepVerifier.create(revoke(system, ORG)).expectNextCount(1).verifyComplete();
            StepVerifier.create(revoke(person, ORG)).expectNextCount(1).verifyComplete();
        }
    }

    // --- C1/C2: list, search and detail ---

    @Nested
    class Query {

        @Test
        void organizationAdminSeesItsOrganization_tenantAdminTheWholeTenant() {
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, TENANT, ORG_ADMIN), null, null), TENANT))
                    .assertNext(d -> assertThat(d.anyOrganization()).isFalse())
                    .verifyComplete();
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, TENANT, TENANT_ADMIN), null, null), TENANT))
                    .assertNext(d -> assertThat(d.anyOrganization()).isTrue())
                    .verifyComplete();
        }

        @Test
        void platformAdminFromThePlatformTenant_canRead() {
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, "platform", PLATFORM_ADMIN), null, null), "platform"))
                    .assertNext(d -> assertThat(d.caller().readOnly()).isTrue())
                    .verifyComplete();
        }

        @ParameterizedTest
        @ValueSource(strings = {QUERY, PowerAuthorizationService.QUERY_FROM_SYSTEM})
        void withoutPower_isDenied(String action) {
            expectReason(inTenant(service.authorize(action, caller(ORG, TENANT, CERTIFY), null, null), TENANT),
                    Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-05: an Onboarding · Execute power whose domain is another tenant gives nothing here. */
        @ParameterizedTest
        @ValueSource(strings = {QUERY, PowerAuthorizationService.QUERY_FROM_SYSTEM})
        void withThePowerOfAnotherTenant_isDenied(String action) {
            Caller foreign = caller(ORG, TENANT, power("organization", OTHER_TENANT, "Onboarding", "Execute"),
                    power("domain", OTHER_TENANT, "Onboarding", "Execute"));
            expectReason(inTenant(service.authorize(action, foreign, null, null), TENANT),
                    Reason.OPERATOR_LACKS_ONBOARDING);
        }

        @Test
        void withATokenOfAnotherTenant_isDenied() {
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, OTHER_TENANT, TENANT_ADMIN), null, null), TENANT))
                    .expectError(TenantMismatchException.class).verify();
        }

        @Test
        void unknownAction_isDeniedByDefault() {
            expectReason(inTenant(service.authorize("Z9", caller(ORG, TENANT, TENANT_ADMIN), null, null), TENANT),
                    Reason.AUTHORIZATION_RULE_MISSING);
        }
    }

    // --- E1..E6, E9: issuance ---

    @Nested
    class Issuance {

        /** AC-01, AC-16, points 9/14: the organization is the caller's, whatever the content, for every type. */
        @ParameterizedTest
        @ValueSource(strings = {EMPLOYEE_TYPE, "doctorid.sd.1", "learcredential.machine.w3c.3"})
        void organizationAdmin_issuesForItsOrganization_whateverTheContent(String type) {
            StepVerifier.create(issue(caller(ORG, TENANT, ORG_ADMIN), type, null, payloadGranting()))
                    .assertNext(a -> assertThat(((es.in2.issuer.backend.shared.domain.policy.IssuanceAuthorization) a)
                            .organizationIdentifier()).isEqualTo(ORG))
                    .verifyComplete();

            assertThat(lastPermitDetails()).containsEntry("processId", "process-1")
                    .containsEntry("organization", ORG)
                    .containsEntry("callerSubject", "sub-" + ORG);
        }

        /** AC-06: only a tenant administrator issues for another organization (E2). */
        @Test
        void organizationAdmin_cannotIssueForAnotherOrganization() {
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, OTHER_ORG, payloadGranting()),
                    Reason.ON_BEHALF_REQUIRES_TENANT_ADMIN);
        }

        /** AC-03, AC-17. */
        @Test
        void tenantAdmin_issuesForItsOwnOrForTheOrganizationItIndicates() {
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()))
                    .assertNext(a -> assertThat(((es.in2.issuer.backend.shared.domain.policy.IssuanceAuthorization) a)
                            .organizationIdentifier()).isEqualTo(ORG))
                    .verifyComplete();
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, OTHER_ORG, payloadGranting()))
                    .assertNext(a -> assertThat(((es.in2.issuer.backend.shared.domain.policy.IssuanceAuthorization) a)
                            .organizationIdentifier()).isEqualTo(OTHER_ORG))
                    .verifyComplete();
        }

        /** AC-09 / E4: the power of tenant administrator is only granted by the platform administrator. */
        @Test
        void tenantAdminPower_isOnlyGrantedByThePlatformAdmin() {
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(TENANT_ADMIN)),
                    Reason.TENANT_ADMIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
            StepVerifier.create(issue(caller(ORG, TENANT, PLATFORM_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(TENANT_ADMIN)))
                    .expectNextCount(1).verifyComplete();
        }

        /** E3, E5: administering an organization and certifying are granted by the tenant administrator. */
        @Test
        void organizationAndCertificationPowers_areGrantedByTheTenantAdmin() {
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(ORG_ADMIN, CERTIFY)))
                    .expectNextCount(1).verifyComplete();
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(ORG_ADMIN)),
                    Reason.ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN);
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(CERTIFY)),
                    Reason.CERTIFICATION_DELEGATION_REQUIRES_TENANT_ADMIN);
        }

        @Test
        void grantingAPowerWithTheTypeInAnotherCase_doesNotSkipTheGrantRule() {
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null,
                            payloadGranting(power("Domain", TENANT, "Onboarding", "Execute"))),
                    Reason.ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN);
        }

        /** E9: a power never leaves its domain -- not even the platform administrator's. */
        @Test
        void grantingAPowerOutsideTheTenant_isOnlyForThePlatformAdmin() {
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(PLATFORM_ADMIN)),
                    Reason.FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null,
                            payloadGranting(power("organization", OTHER_TENANT, "Onboarding", "Execute"))),
                    Reason.FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
        }

        /** E6, FR-09, point 11: product certification needs domain · tenant · Certification · Attest, for any user type. */
        @Test
        void productCertification_needsTheCertificationPowerOfTheTenant() {
            StepVerifier.create(issue(caller(ORG, TENANT, CERTIFY), LABEL_TYPE, null, objectMapper.createObjectNode()))
                    .expectNextCount(1).verifyComplete();
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), LABEL_TYPE, null, objectMapper.createObjectNode()),
                    Reason.CERTIFICATION_POWER_REQUIRED);
            expectReason(issue(caller(ORG, TENANT, power("organization", TENANT, "Certification", "Attest")), LABEL_TYPE, null,
                    objectMapper.createObjectNode()), Reason.CERTIFICATION_POWER_REQUIRED);
            expectReason(issue(caller(ORG, TENANT, power("domain", OTHER_TENANT, "Certification", "Attest")), LABEL_TYPE, null,
                    objectMapper.createObjectNode()), Reason.CERTIFICATION_POWER_REQUIRED);
        }

        /** AC-07. */
        @Test
        void userWithoutPowers_cannotIssue() {
            expectReason(issue(caller(ORG, TENANT), EMPLOYEE_TYPE, null, payloadGranting()), Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-05. */
        @Test
        void onboardingPowerOfAnotherTenant_cannotIssue() {
            expectReason(issue(caller(ORG, TENANT, power("domain", OTHER_TENANT, "Onboarding", "Execute")),
                    EMPLOYEE_TYPE, null, payloadGranting()), Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-04. */
        @Test
        void tokenOfAnotherTenant_cannotIssue() {
            StepVerifier.create(issue(caller(ORG, OTHER_TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()))
                    .expectError(TenantMismatchException.class).verify();
        }

        /** The current profiles name the type by its configuration id: any version of the family is E6. */
        @Test
        void productCertification_isRecognizedByItsConfigurationIdFamily() {
            when(callerResolver.fromSecurityContext()).thenReturn(Mono.just(caller(ORG, TENANT, TENANT_ADMIN)));
            expectReason(inTenant(service.authorizeIssuance("p", "gx.labelcredential.w3c.2", "gx.labelcredential.w3c.2",
                    null, objectMapper.createObjectNode()), TENANT), Reason.CERTIFICATION_POWER_REQUIRED);

            when(callerResolver.fromSecurityContext()).thenReturn(Mono.just(caller(ORG, TENANT, CERTIFY)));
            StepVerifier.create(inTenant(service.authorizeIssuance("p", "gx.labelcredential.w3c.2", "gx.labelcredential.w3c.2",
                    null, objectMapper.createObjectNode()), TENANT)).expectNextCount(1).verifyComplete();
        }

        /** AC-15. */
        @Test
        void typeNotEnabledInTheTenant_isDenied() {
            when(tenantCredentialProfileService.isProfileAllowed("config-id")).thenReturn(Mono.just(false));
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()))
                    .expectError(ResponseStatusException.class).verify();
            lastDenyDetails("credential_type_not_enabled");
        }

        /** AC-11. */
        @Test
        void platformAdminFromThePlatformTenant_cannotIssue() {
            when(callerResolver.fromSecurityContext()).thenReturn(Mono.just(caller(ORG, "platform", PLATFORM_ADMIN)));
            expectReason(inTenant(service.authorizeIssuance("p", "config-id", EMPLOYEE_TYPE, null, payloadGranting()), "platform"),
                    Reason.PLATFORM_TENANT_READ_ONLY);
        }
    }
}
