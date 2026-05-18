package es.in2.issuer.backend.shared.domain.policy.rules;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RequireLearCredentialIssuanceRuleTest {

    private static final String TENANT_DOMAIN = "example.com";
    private static final String TOKEN_TENANT = "example.com";
    private static final String CREDENTIAL_TYPE = "LEARCredentialEmployee";
    private static final String OPERATOR_ORG_ID = "operator-org";
    private static final String OTHER_ORG_ID = "other-org";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private RequireLearCredentialIssuanceRule rule;

    @BeforeEach
    void setUp() {
        rule = new RequireLearCredentialIssuanceRule(objectMapper);
    }

    @Test
    @DisplayName("allows SysAdmin even without Onboarding Execute power")
    void shouldAllowSysAdminBypass() {
        PolicyContext context = context(
                true,
                false,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of()
        );

        JsonNode payload = payload(
                OTHER_ORG_ID,
                List.of(certificationAttestPower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    @Test
    @DisplayName("denies operator without Onboarding Execute power")
    void shouldDenyWhenOperatorDoesNotHaveOnboardingExecutePower() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(certificationAttestPower())
        );

        JsonNode payload = payload(OPERATOR_ORG_ID, List.of());

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("operator lacks Onboarding/Execute power"))
                .verify();
    }

    @Test
    @DisplayName("allows same-org issuance when operator has Onboarding Execute power")
    void shouldAllowSameOrgIssuanceWithOnboardingExecutePower() {
        PolicyContext context = context(
                false,
                false,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(OPERATOR_ORG_ID, List.of());

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    @Test
    @DisplayName("denies payload without mandator organization identifier")
    void shouldDenyWhenPayloadMandatorOrganizationIdentifierIsMissing() {
        PolicyContext context = context(
                false,
                false,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = json("""
                {
                  "mandator": {},
                  "power": []
                }
                """);

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("payload mandator.organizationIdentifier missing"))
                .verify();
    }

    @Test
    @DisplayName("allows TenantAdmin in multi_org tenant to issue on-behalf")
    void shouldAllowTenantAdminMultiOrgOnBehalfIssuance() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(OTHER_ORG_ID, List.of());

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    @Test
    @DisplayName("denies on-behalf issuance when operator is not TenantAdmin")
    void shouldDenyOnBehalfIssuanceWhenOperatorIsNotTenantAdmin() {
        PolicyContext context = context(
                false,
                false,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(OTHER_ORG_ID, List.of());

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("on-behalf issuance requires TenantAdmin")
                        .hasMessageContaining("payload org='" + OTHER_ORG_ID + "'")
                        .hasMessageContaining("operator org='" + OPERATOR_ORG_ID + "'"))
                .verify();
    }

    @Test
    @DisplayName("denies on-behalf issuance when tenant is simple")
    void shouldDenyOnBehalfIssuanceWhenTenantIsSimple() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(OTHER_ORG_ID, List.of());

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("on-behalf issuance not allowed in tenant of type 'simple'"))
                .verify();
    }

    @Test
    @DisplayName("allows TenantAdmin in multi_org tenant to delegate Onboarding Execute on-behalf")
    void shouldAllowTenantAdminMultiOrgToDelegateOnboardingExecuteOnBehalf() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OTHER_ORG_ID,
                List.of(onboardingExecutePower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    @Test
    @DisplayName("denies Onboarding Execute delegation when operator is not TenantAdmin")
    void shouldDenyOnboardingExecuteDelegationWhenOperatorIsNotTenantAdmin() {
        PolicyContext context = context(
                false,
                false,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OTHER_ORG_ID,
                List.of(onboardingExecutePower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("Onboarding/Execute delegation requires TenantAdmin"))
                .verify();
    }

    @Test
    @DisplayName("denies Onboarding Execute delegation when tenant is simple")
    void shouldDenyOnboardingExecuteDelegationWhenTenantIsSimple() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OTHER_ORG_ID,
                List.of(onboardingExecutePower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("Onboarding/Execute delegation only allowed in multi_org tenant")
                        .hasMessageContaining("current: 'simple'"))
                .verify();
    }

    @Test
    @DisplayName("denies Onboarding Execute delegation in same org even for TenantAdmin in multi_org")
    void shouldDenyOnboardingExecuteDelegationWhenPayloadOrgIsSameAsOperatorOrg() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("Onboarding/Execute delegation only allowed on-behalf")
                        .hasMessageContaining("payload mandator org must differ from operator org '" + OPERATOR_ORG_ID + "'"))
                .verify();
    }

    @Test
    @DisplayName("denies Onboarding Execute delegation when payload mandator organization identifier is missing")
    void shouldDenyOnboardingExecuteDelegationWhenPayloadOrgIsMissing() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = json("""
                {
                  "mandator": {},
                  "power": [
                    {
                      "function": "Onboarding",
                      "action": ["Execute"]
                    }
                  ]
                }
                """);

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("Onboarding/Execute delegation only allowed on-behalf")
                        .hasMessageContaining("payload mandator org must differ from operator org '" + OPERATOR_ORG_ID + "'"))
                .verify();
    }

    @Test
    @DisplayName("allows TenantAdmin in multi_org tenant to delegate Certification Attest")
    void shouldAllowTenantAdminMultiOrgToDelegateCertificationAttest() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OPERATOR_ORG_ID,
                List.of(certificationAttestPower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    @Test
    @DisplayName("denies Certification Attest delegation when operator is not TenantAdmin")
    void shouldDenyCertificationAttestDelegationWhenOperatorIsNotTenantAdmin() {
        PolicyContext context = context(
                false,
                false,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OPERATOR_ORG_ID,
                List.of(certificationAttestPower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("Certification/Attest delegation requires TenantAdmin"))
                .verify();
    }

    @Test
    @DisplayName("denies Certification Attest delegation when tenant is simple")
    void shouldDenyCertificationAttestDelegationWhenTenantIsSimple() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = payload(
                OPERATOR_ORG_ID,
                List.of(certificationAttestPower())
        );

        StepVerifier.create(rule.evaluate(context, payload))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(InsufficientPermissionException.class)
                        .hasMessageContaining("Certification/Attest delegation only allowed in multi_org tenant")
                        .hasMessageContaining("current: 'simple'"))
                .verify();
    }

    @Test
    @DisplayName("supports payload powers using TMF aliases")
    void shouldSupportPayloadPowersUsingTmfAliases() {
        PolicyContext context = context(
                false,
                true,
                PolicyContext.TENANT_TYPE_MULTI_ORG,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePower())
        );

        JsonNode payload = json("""
                {
                  "mandator": {
                    "organizationIdentifier": "other-org"
                  },
                  "power": [
                    {
                      "tmf_function": "Onboarding",
                      "tmf_action": ["Execute"]
                    }
                  ]
                }
                """);

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    @Test
    @DisplayName("supports power action as plain string")
    void shouldSupportPowerActionAsPlainString() {
        PolicyContext context = context(
                false,
                false,
                PolicyContext.TENANT_TYPE_SIMPLE,
                OPERATOR_ORG_ID,
                List.of(onboardingExecutePowerWithStringAction())
        );

        JsonNode payload = payload(OPERATOR_ORG_ID, List.of());

        StepVerifier.create(rule.evaluate(context, payload))
                .verifyComplete();
    }

    private PolicyContext context(
            boolean sysAdmin,
            boolean tenantAdmin,
            String tenantType,
            String organizationIdentifier,
            List<Power> powers
    ) {
        return new PolicyContext(
                organizationIdentifier,
                powers,
                null,
                null,
                CREDENTIAL_TYPE,
                sysAdmin,
                tenantAdmin,
                TENANT_DOMAIN,
                TOKEN_TENANT,
                tenantType
        );
    }

    private JsonNode payload(String mandatorOrgId, List<Power> powers) {
        return objectMapper.valueToTree(new LearCredentialPayload(
                new Mandator(mandatorOrgId),
                powers
        ));
    }

    private JsonNode json(String json) {
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid test JSON", e);
        }
    }

    private Power onboardingExecutePower() {
        return Power.builder()
                .function("Onboarding")
                .action(List.of("Execute"))
                .build();
    }

    private Power onboardingExecutePowerWithStringAction() {
        return Power.builder()
                .function("Onboarding")
                .action("Execute")
                .build();
    }

    private Power certificationAttestPower() {
        return Power.builder()
                .function("Certification")
                .action(List.of("Attest"))
                .build();
    }

    private record LearCredentialPayload(
            Mandator mandator,
            List<Power> power
    ) {
    }

    private record Mandator(
            String organizationIdentifier
    ) {
    }
}