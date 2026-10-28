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
import es.in2.issuer.backend.shared.domain.model.port.CallerProvider;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationDecision;
import es.in2.issuer.backend.shared.domain.policy.AuthorizationMatrix.Scope;
import es.in2.issuer.backend.shared.domain.policy.Caller;
import es.in2.issuer.backend.shared.domain.policy.IssuanceAuthorization;
import es.in2.issuer.backend.shared.domain.policy.RecognizedCaller;
import es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.FileAuthorizationMatrixProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.stream.Stream;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.ARCHIVE;
import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.QUERY;
import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.QUERY_FROM_SYSTEM;
import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.REVOKE;
import static es.in2.issuer.backend.shared.domain.policy.service.PowerAuthorizationService.WITHDRAW;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * EUD-272 / EUD-253: every action decided by the caller's powers and the organization stored with
 * the resource, with the bundled matrix. Each action has a negative case without the power and one
 * from another tenant (tech-debt.md, "Para el diseño y las pruebas" 3).
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
    private CallerProvider callerProvider;
    private TenantCredentialProfileService tenantCredentialProfileService;
    private AuditService auditService;
    private PowerAuthorizationServiceImpl service;

    @BeforeEach
    void setUp() {
        callerProvider = mock(CallerProvider.class);
        tenantCredentialProfileService = mock(TenantCredentialProfileService.class);
        auditService = mock(AuditService.class);
        when(tenantCredentialProfileService.isProfileAllowed(anyString())).thenReturn(Mono.just(true));
        service = new PowerAuthorizationServiceImpl(new FileAuthorizationMatrixProvider("", mock(AuditService.class)),
                callerProvider, tenantCredentialProfileService, auditService, objectMapper);
    }

    // --- helpers ---

    private static Power power(String type, String domain, String function, String action) {
        return new Power(List.of(action), domain, function, type);
    }

    private static String attestationOf(String org) {
        return "urn:uuid:attestation-" + org;
    }

    private static Caller caller(String org, String tokenTenant, Power... powers) {
        return new Caller(org, List.of(powers), tokenTenant, "learcredential.machine.w3c.3", "jti-" + org, attestationOf(org));
    }

    private <T> Mono<T> inTenant(Mono<T> mono, String tenant) {
        return mono.contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, tenant));
    }

    private Mono<AuthorizationDecision> decide(String action, Caller caller, String resourceOrg) {
        return inTenant(service.authorize(action, caller, resourceOrg, "issuance-1"), TENANT);
    }

    private Mono<IssuanceAuthorization> issue(Caller caller, String credentialType, String organization, JsonNode payload) {
        return issueIn(TENANT, caller, credentialType, organization, payload);
    }

    private Mono<IssuanceAuthorization> issueIn(String tenant, Caller caller, String credentialType, String organization,
                                                JsonNode payload) {
        when(callerProvider.current()).thenReturn(Mono.just(caller));
        return inTenant(service.authorizeIssuance("process-1", "config-id", credentialType, organization, payload), tenant);
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

        private String userType(Caller caller) {
            return inTenant(service.recognize(caller), TENANT).map(RecognizedCaller::userType).block();
        }

        @Test
        void PowerAuthorizationService_recognize_recognizesEachUserTypeByItsPowerAlone() {
            assertThat(userType(caller(ORG, TENANT, PLATFORM_ADMIN))).isEqualTo(RecognizedCaller.PLATFORM_ADMIN);
            assertThat(userType(caller(ORG, TENANT, TENANT_ADMIN))).isEqualTo(RecognizedCaller.TENANT_ADMIN);
            assertThat(userType(caller(ORG, TENANT, ORG_ADMIN))).isEqualTo(RecognizedCaller.ORGANIZATION_ADMIN);
            assertThat(userType(caller(ORG, TENANT, CERTIFY))).isEqualTo(RecognizedCaller.USER);
            assertThat(userType(caller(ORG, TENANT))).isEqualTo(RecognizedCaller.USER);
        }

        @Test
        void PowerAuthorizationService_recognize_platformAdminActsAsTenantAdminAndIsASecurityActor() {
            StepVerifier.create(inTenant(service.recognize(caller(ORG, TENANT, PLATFORM_ADMIN)), TENANT))
                    .assertNext(r -> {
                        assertThat(r.actsAs()).isEqualTo(RecognizedCaller.TENANT_ADMIN);
                        assertThat(r.securityAction()).isTrue();
                        assertThat(r.readOnly()).isFalse();
                    })
                    .verifyComplete();
        }

        @Test
        void PowerAuthorizationService_recognize_comparesThePowerTypeInLowercaseOnly() {
            assertThat(userType(caller(ORG, TENANT, power("Domain", TENANT, "Onboarding", "Execute"))))
                    .isEqualTo(RecognizedCaller.USER);
            assertThat(userType(caller(ORG, TENANT, power("Organization", TENANT, "Onboarding", "Execute"))))
                    .isEqualTo(RecognizedCaller.USER);
        }

        /** FR-02 also for the role-only callers (GET /me, catalog): S3 of the EUD-272 security review. */
        @Test
        void PowerAuthorizationService_recognize_deniesATokenOfAnotherTenantAndTracesIt() {
            // Given: a platform administrator whose token was issued for the platform tenant
            Caller platformToken = caller(ORG, "platform", PLATFORM_ADMIN);

            // When / Then: it cannot be recognized in sandbox, where it would not be read-only
            StepVerifier.create(inTenant(service.recognize(platformToken), TENANT))
                    .expectError(TenantMismatchException.class)
                    .verify();
            assertThat(lastDenyDetails("tenant_mismatch")).containsEntry("tenant", TENANT);
        }

        @Test
        void PowerAuthorizationService_recognize_withoutTenantHeaderFailsClosed() {
            StepVerifier.create(service.recognize(caller(ORG, TENANT, TENANT_ADMIN)))
                    .expectError(TenantMismatchException.class)
                    .verify();
        }
    }

    // --- R1, E7, R2: revoke, withdraw and archive -- the same rule on a stored resource ---

    @Nested
    class ResourceActions {

        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_organizationAdminActsOnItsOwnOrganization(String action) {
            StepVerifier.create(decide(action, caller(ORG, TENANT, ORG_ADMIN), ORG)).expectNextCount(1).verifyComplete();
        }

        /** AC-02 / Jira AC: another organization → issuance_not_found (existence not disclosed) + trace. */
        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_organizationAdminOnAnotherOrganizationFailsAsNotFound(String action) {
            // When / Then
            StepVerifier.create(decide(action, caller(ORG, TENANT, ORG_ADMIN), OTHER_ORG))
                    .expectError(IssuanceNotFoundException.class)
                    .verify();

            // Then: the trace keeps the real reason
            assertThat(lastDenyDetails("resource_out_of_scope")).containsEntry("action", action)
                    .containsEntry("userType", RecognizedCaller.ORGANIZATION_ADMIN)
                    .containsEntry("resourceOrganization", OTHER_ORG)
                    .containsEntry("callerOrganization", ORG);
        }

        /** A process stored without an organization (before EUD-272) is passed as "", never matched by an organization. */
        @Test
        void PowerAuthorizationService_authorize_organizationAdminOnAProcessWithoutOrganizationFailsAsNotFound() {
            StepVerifier.create(decide(REVOKE, caller(ORG, TENANT, ORG_ADMIN), ""))
                    .expectError(IssuanceNotFoundException.class)
                    .verify();
        }

        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_tenantAdminActsOnAnyOrganizationOfTheTenant(String action) {
            StepVerifier.create(decide(action, caller(ORG, TENANT, TENANT_ADMIN), OTHER_ORG))
                    .assertNext(d -> assertThat(d.scope()).isEqualTo(Scope.ANY_ORGANIZATION))
                    .verifyComplete();
        }

        /** AC-10. */
        @Test
        void PowerAuthorizationService_authorize_platformAdminInsideATenantIsPermittedAsItsAdministratorWithSecurityTrace() {
            StepVerifier.create(decide(REVOKE, caller(ORG, TENANT, PLATFORM_ADMIN), OTHER_ORG)).expectNextCount(1).verifyComplete();

            assertThat(lastPermitDetails()).containsEntry("securityAction", true)
                    .containsEntry("actsAs", RecognizedCaller.TENANT_ADMIN);
        }

        /** AC-11: every action that writes is denied from the platform tenant, and traced. */
        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_platformAdminFromThePlatformTenantCannotWrite(String action) {
            // Given
            Caller platformAdmin = caller(ORG, "platform", PLATFORM_ADMIN);

            // When / Then
            expectReason(inTenant(service.authorize(action, platformAdmin, OTHER_ORG, "issuance-1"), "platform"),
                    Reason.PLATFORM_TENANT_READ_ONLY);
            assertThat(lastDenyDetails(Reason.PLATFORM_TENANT_READ_ONLY.getCode())).containsEntry("action", action);
        }

        /** AC-07, W3: a user without powers. */
        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_userWithoutPowersIsDenied(String action) {
            expectReason(decide(action, caller(ORG, TENANT), ORG), Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-05. */
        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_thePowerOfAnotherTenantIsDenied(String action) {
            expectReason(decide(action, caller(ORG, TENANT, power("domain", OTHER_TENANT, "Onboarding", "Execute")), ORG),
                    Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-04, FR-02: also for the platform administrator. */
        @ParameterizedTest
        @ValueSource(strings = {REVOKE, WITHDRAW, ARCHIVE})
        void PowerAuthorizationService_authorize_aTokenOfAnotherTenantIsDeniedEvenForThePlatformAdmin(String action) {
            StepVerifier.create(decide(action, caller(ORG, OTHER_TENANT, ORG_ADMIN), ORG))
                    .expectError(TenantMismatchException.class).verify();
            StepVerifier.create(decide(action, caller(ORG, "platform", PLATFORM_ADMIN), ORG))
                    .expectError(TenantMismatchException.class).verify();
            lastDenyDetails("tenant_mismatch");
        }

        @Test
        void PowerAuthorizationService_authorize_withoutTenantHeaderFailsClosed() {
            StepVerifier.create(service.authorize(REVOKE, caller(ORG, TENANT, TENANT_ADMIN), ORG, "issuance-1"))
                    .expectError(TenantMismatchException.class).verify();
        }

        /** AC-08: a system and a person with the same powers get the same decision. */
        @Test
        void PowerAuthorizationService_authorize_personAndSystemWithTheSamePowersGetTheSameDecision() {
            // Given
            Caller system = new Caller(ORG, List.of(ORG_ADMIN), TENANT, "learcredential.machine.w3c.3", "j");
            Caller person = new Caller(ORG, List.of(ORG_ADMIN), TENANT, "learcredential.employee.w3c.4", "j");

            // When / Then
            StepVerifier.create(decide(REVOKE, system, OTHER_ORG)).expectError(IssuanceNotFoundException.class).verify();
            StepVerifier.create(decide(REVOKE, person, OTHER_ORG)).expectError(IssuanceNotFoundException.class).verify();
            StepVerifier.create(decide(REVOKE, system, ORG)).expectNextCount(1).verifyComplete();
            StepVerifier.create(decide(REVOKE, person, ORG)).expectNextCount(1).verifyComplete();
        }
    }

    // --- C1/C2: list, search and detail ---

    @Nested
    class Query {

        @Test
        void PowerAuthorizationService_authorize_organizationAdminSeesItsOrganizationAndTenantAdminTheWholeTenant() {
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, TENANT, ORG_ADMIN), null, null), TENANT))
                    .assertNext(d -> assertThat(d.anyOrganization()).isFalse())
                    .verifyComplete();
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, TENANT, TENANT_ADMIN), null, null), TENANT))
                    .assertNext(d -> assertThat(d.anyOrganization()).isTrue())
                    .verifyComplete();
        }

        /** W2: the detail of another organization's attestation is a denial in the trace, not a permit. */
        @Test
        void PowerAuthorizationService_authorize_detailOfAnotherOrganizationIsTracedAsOutOfScope() {
            StepVerifier.create(decide(QUERY, caller(ORG, TENANT, ORG_ADMIN), OTHER_ORG))
                    .expectError(IssuanceNotFoundException.class).verify();

            lastDenyDetails("resource_out_of_scope");
            verify(auditService, never()).auditSuccess(eq("authorization.permit"), any(), any(), any(), any());
        }

        @Test
        void PowerAuthorizationService_authorize_platformAdminFromThePlatformTenantCanRead() {
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, "platform", PLATFORM_ADMIN), null, null), "platform"))
                    .assertNext(d -> assertThat(d.caller().readOnly()).isTrue())
                    .verifyComplete();
        }

        @ParameterizedTest
        @ValueSource(strings = {QUERY, QUERY_FROM_SYSTEM})
        void PowerAuthorizationService_authorize_withoutPowerIsDenied(String action) {
            expectReason(inTenant(service.authorize(action, caller(ORG, TENANT, CERTIFY), null, null), TENANT),
                    Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-05: an Onboarding · Execute power whose domain is another tenant gives nothing here. */
        @ParameterizedTest
        @ValueSource(strings = {QUERY, QUERY_FROM_SYSTEM})
        void PowerAuthorizationService_authorize_thePowerOfAnotherTenantIsDenied(String action) {
            Caller foreign = caller(ORG, TENANT, power("organization", OTHER_TENANT, "Onboarding", "Execute"),
                    power("domain", OTHER_TENANT, "Onboarding", "Execute"));
            expectReason(inTenant(service.authorize(action, foreign, null, null), TENANT),
                    Reason.OPERATOR_LACKS_ONBOARDING);
        }

        @Test
        void PowerAuthorizationService_authorize_aTokenOfAnotherTenantCannotQuery() {
            StepVerifier.create(inTenant(service.authorize(QUERY, caller(ORG, OTHER_TENANT, TENANT_ADMIN), null, null), TENANT))
                    .expectError(TenantMismatchException.class).verify();
        }

        /** C2 for a system (machine attestation), C1 for a person: same powers, same scope (AC-08). */
        @ParameterizedTest
        @CsvSource({"learcredential.machine.w3c.3, C2", "learcredential.machine.sd.1, C2", "LEARCredentialMachine, C2",
                "learcredential.employee.sd.1, C1", "LEARCredentialEmployee, C1"})
        void PowerAuthorizationService_authorizeQuery_aSystemIsDecidedAsC2AndAPersonAsC1(String credentialType, String action) {
            // Given
            when(callerProvider.current()).thenReturn(Mono.just(new Caller(ORG, List.of(ORG_ADMIN), TENANT, credentialType, "j")));

            // When / Then
            StepVerifier.create(inTenant(service.authorizeQuery(null, null), TENANT))
                    .assertNext(d -> {
                        assertThat(d.actionId()).isEqualTo(action);
                        assertThat(d.anyOrganization()).isFalse();
                    })
                    .verifyComplete();
        }

        @Test
        void PowerAuthorizationService_authorize_unknownActionIsDeniedByDefault() {
            expectReason(inTenant(service.authorize("Z9", caller(ORG, TENANT, TENANT_ADMIN), null, null), TENANT),
                    Reason.AUTHORIZATION_RULE_MISSING);
        }
    }

    // --- Task criterion: every action has a negative test without its power and one with another tenant ---

    /** Action, holder of its power, a caller of the tenant without it, type, organization, granted powers. */
    static Stream<Arguments> issuanceActions() {
        return Stream.of(
                Arguments.of("E1", List.of(ORG_ADMIN), List.<Power>of(), EMPLOYEE_TYPE, null, List.<Power>of()),
                Arguments.of("E2", List.of(TENANT_ADMIN), List.of(ORG_ADMIN), EMPLOYEE_TYPE, OTHER_ORG, List.<Power>of()),
                Arguments.of("E3", List.of(TENANT_ADMIN), List.of(ORG_ADMIN), EMPLOYEE_TYPE, null, List.of(ORG_ADMIN)),
                Arguments.of("E4", List.of(PLATFORM_ADMIN), List.of(TENANT_ADMIN), EMPLOYEE_TYPE, null, List.of(TENANT_ADMIN)),
                Arguments.of("E5", List.of(TENANT_ADMIN), List.of(ORG_ADMIN), EMPLOYEE_TYPE, null, List.of(CERTIFY)),
                Arguments.of("E6", List.of(CERTIFY), List.of(TENANT_ADMIN), LABEL_TYPE, null, List.<Power>of()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("issuanceActions")
    void PowerAuthorizationService_authorizeIssuance_eachActionIsPermittedWithItsPowerOnlyAndOnlyInItsTenant(
            String action, List<Power> holder, List<Power> withoutIt, String type, String organization, List<Power> granted) {
        JsonNode payload = payloadGranting(granted.toArray(Power[]::new));

        // With its power, in its tenant: permitted, and the action is part of the decision
        StepVerifier.create(issue(caller(ORG, TENANT, holder.toArray(Power[]::new)), type, organization, payload))
                .assertNext(a -> assertThat(a.actionIds()).contains(action))
                .verifyComplete();

        // Negative 1 -- without the power: denied
        StepVerifier.create(issue(caller(ORG, TENANT, withoutIt.toArray(Power[]::new)), type, organization, payload))
                .expectError(LearIssuancePolicyException.class).verify();

        // Negative 2 -- another tenant: the same powers in a token of another tenant are denied...
        StepVerifier.create(issue(caller(ORG, OTHER_TENANT, holder.toArray(Power[]::new)), type, organization, payload))
                .expectError(TenantMismatchException.class).verify();

        // ...and so is the power itself when its domain is another tenant (for E4, System · Administration
        // of a domain that is not the platform's recognizes no administrator)
        Power[] foreign = holder.stream()
                .map(p -> power(p.type(), OTHER_TENANT, p.function(), actionOf(p)))
                .toArray(Power[]::new);
        StepVerifier.create(issue(caller(ORG, TENANT, foreign), type, organization, payload))
                .expectError(LearIssuancePolicyException.class).verify();
    }

    private static String actionOf(Power p) {
        return p.action() instanceof List<?> list && !list.isEmpty() ? String.valueOf(list.get(0)) : String.valueOf(p.action());
    }

    // --- E1..E6, E9: issuance ---

    @Nested
    class Issuance {

        /** AC-01, AC-16, points 9/14: the organization is the caller's, whatever the content, for every type. */
        @ParameterizedTest
        @ValueSource(strings = {EMPLOYEE_TYPE, "doctorid.sd.1", "learcredential.machine.w3c.3"})
        void PowerAuthorizationService_authorizeIssuance_organizationAdminIssuesForItsOrganizationWhateverTheContent(String type) {
            // Given: a payload whose mandator is another organization
            JsonNode payload = payloadGranting();

            // When / Then
            StepVerifier.create(issue(caller(ORG, TENANT, ORG_ADMIN), type, null, payload))
                    .assertNext(a -> assertThat(a.organizationIdentifier()).isEqualTo(ORG))
                    .verifyComplete();
            assertThat(lastPermitDetails()).containsEntry("processId", "process-1")
                    .containsEntry("organization", ORG)
                    .containsEntry("callerAttestationId", attestationOf(ORG));
        }

        /** AC-06: only a tenant administrator issues for another organization (E2). */
        @Test
        void PowerAuthorizationService_authorizeIssuance_organizationAdminCannotIssueForAnotherOrganization() {
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, OTHER_ORG, payloadGranting()),
                    Reason.ON_BEHALF_REQUIRES_TENANT_ADMIN);
        }

        /** AC-03, AC-17. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_tenantAdminIssuesForItsOwnOrForTheOrganizationItIndicates() {
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()))
                    .assertNext(a -> assertThat(a.organizationIdentifier()).isEqualTo(ORG))
                    .verifyComplete();
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, OTHER_ORG, payloadGranting()))
                    .assertNext(a -> assertThat(a.organizationIdentifier()).isEqualTo(OTHER_ORG))
                    .verifyComplete();
        }

        /** AC-09 / E4: the power of tenant administrator is only granted by the platform administrator. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_tenantAdminPowerIsOnlyGrantedByThePlatformAdmin() {
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(TENANT_ADMIN)),
                    Reason.TENANT_ADMIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
            StepVerifier.create(issue(caller(ORG, TENANT, PLATFORM_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(TENANT_ADMIN)))
                    .expectNextCount(1).verifyComplete();
        }

        /** E3, E5: administering an organization and certifying are granted by the tenant administrator. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_organizationAndCertificationPowersAreGrantedByTheTenantAdmin() {
            StepVerifier.create(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(ORG_ADMIN, CERTIFY)))
                    .expectNextCount(1).verifyComplete();
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(ORG_ADMIN)),
                    Reason.ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN);
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(CERTIFY)),
                    Reason.CERTIFICATION_DELEGATION_REQUIRES_TENANT_ADMIN);
        }

        @Test
        void PowerAuthorizationService_authorizeIssuance_aPowerTypeInAnotherCaseDoesNotSkipTheGrantRule() {
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null,
                            payloadGranting(power("Domain", TENANT, "Onboarding", "Execute"))),
                    Reason.ONBOARDING_DELEGATION_REQUIRES_TENANT_ADMIN);
        }

        /**
         * Round 4 of the EUD-272 security review (F5-R): a power that names a field twice, plain and with its
         * tmf_ alias, is decided under both readings, whichever one a consumer of the attestation reads.
         */
        @ParameterizedTest
        @ValueSource(strings = {
                "{\"type\":\"organization\",\"domain\":\"sandbox\",\"function\":\"Onboarding\",\"tmf_function\":\"Nope\",\"action\":[\"Execute\"]}",
                "{\"type\":\"organization\",\"domain\":\"sandbox\",\"tmf_function\":\"Onboarding\",\"function\":\"Nope\",\"action\":[\"Execute\"]}"
        })
        void PowerAuthorizationService_authorizeIssuance_aPowerHiddenBehindItsTmfAliasStillNeedsItsGrantRule(String power)
                throws Exception {
            // Given: an organization administrator granting the tenant administrator power under one of the two readings
            ObjectNode payload = objectMapper.createObjectNode();
            payload.putArray("power").add(objectMapper.readTree(power));

            // When / Then
            expectReason(issue(caller(ORG, TENANT, ORG_ADMIN), EMPLOYEE_TYPE, null, payload),
                    Reason.TENANT_ADMIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
        }

        /** E9: a power never leaves its domain -- not even the platform administrator's. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_grantingAPowerOutsideTheTenantIsOnlyForThePlatformAdmin() {
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting(PLATFORM_ADMIN)),
                    Reason.FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null,
                            payloadGranting(power("organization", OTHER_TENANT, "Onboarding", "Execute"))),
                    Reason.FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
        }

        /** S7 of the EUD-272 security review: a tenant named like the platform domain does not own its power. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_thePlatformPowerIsOutsideATenantNamedLikeThePlatform() {
            // Given: an organization administrator of a tenant called "eudistack"
            Caller orgAdmin = caller(ORG, "eudistack", power("domain", "eudistack", "Onboarding", "Execute"));

            // When / Then: granting System · Administration still needs E9 (platform administrator only)
            expectReason(issueIn("eudistack", orgAdmin, EMPLOYEE_TYPE, null, payloadGranting(PLATFORM_ADMIN)),
                    Reason.FOREIGN_DOMAIN_DELEGATION_REQUIRES_PLATFORM_ADMIN);
        }

        /** E6, FR-09, point 11: product certification needs domain · tenant · Certification · Attest, for any user type. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_productCertificationNeedsTheCertificationPowerOfTheTenant() {
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
        void PowerAuthorizationService_authorizeIssuance_userWithoutPowersCannotIssue() {
            expectReason(issue(caller(ORG, TENANT), EMPLOYEE_TYPE, null, payloadGranting()), Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-05. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_onboardingPowerOfAnotherTenantCannotIssue() {
            expectReason(issue(caller(ORG, TENANT, power("domain", OTHER_TENANT, "Onboarding", "Execute")),
                    EMPLOYEE_TYPE, null, payloadGranting()), Reason.OPERATOR_LACKS_ONBOARDING);
        }

        /** AC-04. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_tokenOfAnotherTenantCannotIssue() {
            StepVerifier.create(issue(caller(ORG, OTHER_TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()))
                    .expectError(TenantMismatchException.class).verify();
        }

        /** The current profiles name the type by its configuration id: any version of the family is E6. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_productCertificationIsRecognizedByItsConfigurationIdFamily() {
            when(callerProvider.current()).thenReturn(Mono.just(caller(ORG, TENANT, TENANT_ADMIN)));
            expectReason(inTenant(service.authorizeIssuance("p", "gx.labelcredential.w3c.2", "gx.labelcredential.w3c.2",
                    null, objectMapper.createObjectNode()), TENANT), Reason.CERTIFICATION_POWER_REQUIRED);

            when(callerProvider.current()).thenReturn(Mono.just(caller(ORG, TENANT, CERTIFY)));
            StepVerifier.create(inTenant(service.authorizeIssuance("p", "gx.labelcredential.w3c.2", "gx.labelcredential.w3c.2",
                    null, objectMapper.createObjectNode()), TENANT)).expectNextCount(1).verifyComplete();
        }

        /** AC-15: denied like any other rule, with its stable reason (N3). */
        @Test
        void PowerAuthorizationService_authorizeIssuance_typeNotEnabledInTheTenantIsDenied() {
            // Given
            when(tenantCredentialProfileService.isProfileAllowed("config-id")).thenReturn(Mono.just(false));

            // When / Then
            expectReason(issue(caller(ORG, TENANT, TENANT_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()),
                    Reason.CREDENTIAL_TYPE_NOT_ENABLED);
            lastDenyDetails(Reason.CREDENTIAL_TYPE_NOT_ENABLED.getCode());
        }

        /** AC-11. */
        @Test
        void PowerAuthorizationService_authorizeIssuance_platformAdminFromThePlatformTenantCannotIssue() {
            expectReason(issueIn("platform", caller(ORG, "platform", PLATFORM_ADMIN), EMPLOYEE_TYPE, null, payloadGranting()),
                    Reason.PLATFORM_TENANT_READ_ONLY);
        }
    }

    // --- FR-13: the trace of every decision ---

    /** AC-14: every decision, permitted or denied, is audited with who, power, resource, result and reason. */
    @Nested
    class Audit {

        @Test
        void PowerAuthorizationService_authorize_permittedDecisionIsAuditedWithWhoPowerAndResource() {
            // When
            StepVerifier.create(decide(REVOKE, caller(ORG, TENANT, TENANT_ADMIN), OTHER_ORG)).expectNextCount(1).verifyComplete();

            // Then
            verify(auditService).auditSuccess(eq("authorization.permit"), eq(attestationOf(ORG)), eq("action"), eq(REVOKE), any());
            assertThat(lastPermitDetails()).containsEntry("callerAttestationId", attestationOf(ORG))
                    .containsEntry("callerOrganization", ORG)
                    .containsEntry("recognizedByPower", "organization · sandbox · Onboarding · Execute")
                    .containsEntry("resourceOrganization", OTHER_ORG)
                    .containsEntry("resourceId", "issuance-1")
                    .containsEntry("scope", Scope.ANY_ORGANIZATION.value());
        }

        @Test
        void PowerAuthorizationService_authorize_deniedDecisionIsAuditedWithWhoPowerResourceAndReason() {
            // When
            StepVerifier.create(decide(REVOKE, caller(ORG, TENANT, ORG_ADMIN), OTHER_ORG))
                    .expectError(IssuanceNotFoundException.class).verify();

            // Then
            verify(auditService).auditFailure(eq("authorization.deny"), eq(attestationOf(ORG)), eq("resource_out_of_scope"), any());
            assertThat(lastDenyDetails("resource_out_of_scope"))
                    .containsEntry("recognizedByPower", "domain · sandbox · Onboarding · Execute")
                    .containsEntry("resourceOrganization", OTHER_ORG)
                    .containsEntry("resourceId", "issuance-1");
            verify(auditService, never()).auditSuccess(eq("authorization.permit"), any(), any(), any(), any());
        }

        @Test
        void PowerAuthorizationService_authorizeIssuance_deniedForAMissingPowerIsAuditedWithThePowerEvaluated() {
            // Given
            when(callerProvider.current()).thenReturn(Mono.just(caller(ORG, TENANT, ORG_ADMIN)));

            // When
            expectReason(inTenant(service.authorizeIssuance("process-1", "gx.labelcredential.w3c.2", LABEL_TYPE,
                    null, objectMapper.createObjectNode()), TENANT), Reason.CERTIFICATION_POWER_REQUIRED);

            // Then
            assertThat(lastDenyDetails(Reason.CERTIFICATION_POWER_REQUIRED.getCode()))
                    .containsEntry("powerEvaluated", "domain · {tenant} · Certification · Attest")
                    .containsEntry("processId", "process-1");
        }

        /** §10.3: the trace identifies the caller by its attestation, never by personal data. */
        @Test
        void PowerAuthorizationService_authorize_traceCarriesNoSubject() {
            // When
            StepVerifier.create(decide(REVOKE, caller(ORG, TENANT, TENANT_ADMIN), ORG)).expectNextCount(1).verifyComplete();

            // Then
            assertThat(lastPermitDetails()).doesNotContainKeys("callerSubject", "subject", "email");
        }

        @Test
        void PowerAuthorizationService_authorize_actorFallsBackToTheTokenIdWithoutAttestationId() {
            // Given
            Caller withoutAttestation = new Caller(ORG, List.of(TENANT_ADMIN), TENANT, EMPLOYEE_TYPE, "jti-only");

            // When
            StepVerifier.create(decide(REVOKE, withoutAttestation, ORG)).expectNextCount(1).verifyComplete();

            // Then
            verify(auditService).auditSuccess(eq("authorization.permit"), eq("jti-only"), eq("action"), eq(REVOKE), any());
        }
    }
}
