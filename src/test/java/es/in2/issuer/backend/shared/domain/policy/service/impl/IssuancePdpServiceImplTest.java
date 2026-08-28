package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InsufficientPermissionException;
import es.in2.issuer.backend.shared.domain.exception.ParseErrorException;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.policy.PolicyContext;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCertificationIssuanceRule;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCredentialProfileAllowedForTenantRule;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuancePdpServiceImplTest {

    private static final String OPERATOR_ORG = "OPERATOR_ORG";
    private static final String OTHER_ORG = "OTHER_ORG";
    private static final String EMPLOYEE_CFG = "learcredential.employee.w3c.4";
    private static final String MACHINE_CFG = "learcredential.machine.w3c.3";
    private static final String CERT_CFG = "gx.labelcredential.w3c.1";

    @Mock private PolicyContextFactory policyContextFactory;
    @Mock private ObjectMapper objectMapper;
    @Mock private JWTService jwtService;
    @Mock private VerifierService verifierService;
    @Mock private DynamicCredentialParser credentialParser;
    @Mock private CredentialProfileRegistry credentialProfileRegistry;
    @Mock private AuditService auditService;
    @Mock private RequireCredentialProfileAllowedForTenantRule requireCredentialProfileAllowedForTenantRule;

    private IssuancePdpServiceImpl issuancePdpService;
    private final ObjectMapper realMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        RequireCertificationIssuanceRule certificationRule = new RequireCertificationIssuanceRule(
                verifierService, jwtService, objectMapper, credentialParser);

        lenient().when(requireCredentialProfileAllowedForTenantRule.evaluate(any(), any()))
                .thenReturn(Mono.empty());

        issuancePdpService = new IssuancePdpServiceImpl(
                policyContextFactory,
                objectMapper,
                certificationRule,
                requireCredentialProfileAllowedForTenantRule,
                credentialProfileRegistry,
                auditService
        );
    }

    private CredentialProfile profileWithRule(String configId, String ruleName) {
        return CredentialProfile.builder()
                .credentialConfigurationId(configId)
                .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                        .rules(List.of(ruleName))
                        .build())
                .build();
    }

    private Context withSecurityContext(String tokenValue) {
        Jwt jwt = Jwt.withTokenValue(tokenValue)
                .header("alg", "none")
                .claim("sub", "test")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        return ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt));
    }

    private PolicyContext ctx(List<Power> powers, String orgId, boolean sysAdmin,
                              boolean tenantAdmin, String tenantType) {
        JsonNode cred = realMapper.createObjectNode();
        CredentialProfile profile = mock(CredentialProfile.class);
        lenient().when(credentialParser.extractOrganizationId(cred, profile)).thenReturn(orgId);
        return new PolicyContext(orgId, powers, cred, profile, EMPLOYEE_CFG,
                sysAdmin, tenantAdmin, "sandbox", "sandbox", tenantType);
    }

    private com.fasterxml.jackson.databind.node.ObjectNode payloadWith(String mandatorOrgId,
                                                                      List<Power> powers) {
        com.fasterxml.jackson.databind.node.ObjectNode payload = realMapper.createObjectNode();
        payload.putObject("mandator").put("organizationIdentifier", mandatorOrgId);
        com.fasterxml.jackson.databind.node.ArrayNode arr = payload.putArray("power");
        for (Power p : powers) {
            com.fasterxml.jackson.databind.node.ObjectNode node = arr.addObject();
            node.put("function", p.function());
            if (p.action() instanceof List<?> actions) {
                com.fasterxml.jackson.databind.node.ArrayNode a = node.putArray("action");
                actions.forEach(v -> a.add(v.toString()));
            } else {
                node.put("action", p.action().toString());
            }
        }
        return payload;
    }

    private void stubPayloadPowerConversion() {
        lenient().when(objectMapper.convertValue(any(JsonNode.class), any(TypeReference.class)))
                .thenAnswer(inv -> realMapper.convertValue((JsonNode) inv.getArgument(0),
                        new TypeReference<List<Power>>() {}));
    }

    // ─── Profile resolution ────────────────────────────────────────────────

    @Test
    void authorize_fails_whenProfileUnknown() {
        when(credentialProfileRegistry.getByConfigurationId("Unknown")).thenReturn(null);

        StepVerifier.create(issuancePdpService.authorize("Unknown", mock(JsonNode.class), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("No profile found for Unknown"))
                .verify();
    }

    @Test
    void authorize_propagates_parseErrorFromContextFactory() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.error(new ParseErrorException("Invalid token")));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG, mock(JsonNode.class), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof ParseErrorException
                        && e.getMessage().contains("Invalid token"))
                .verify();
    }

    // ─── LEAR rule: SysAdmin bypass ────────────────────────────────────────

    @Test
    void authorize_success_sysAdminBypass() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        PolicyContext ctx = ctx(List.of(), OPERATOR_ORG, true, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG, mock(JsonNode.class), "id")
                        .contextWrite(withSecurityContext("t")))
                .verifyComplete();
    }

    // ─── LEAR rule: power base ─────────────────────────────────────────────

    @Test
    void authorize_fails_whenOperatorLacksOnboardingExecute() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        PolicyContext ctx = ctx(List.of(), OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                        payloadWith(OPERATOR_ORG, List.of()), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("lacks Onboarding/Execute"))
                .verify();
    }

    // ─── LEAR rule: escalation prevention ──────────────────────────────────

    @Test
    void authorize_fails_whenPayloadDelegates_OnboardingExecute() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        List<Power> delegated = List.of(Power.builder().function("Onboarding").action("Execute").build());

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                                payloadWith(OPERATOR_ORG, delegated), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("Onboarding/Execute delegation requires TenantAdmin"))
                .verify();
    }

    @Test
    void authorize_fails_whenPayloadDelegates_CertificationAttest() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        List<Power> delegated = List.of(Power.builder().function("Certification").action("Attest").build());

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                                payloadWith(OPERATOR_ORG, delegated), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("Certification/Attest delegation requires TenantAdmin"))
                .verify();
    }

    // ─── LEAR rule: org scope ──────────────────────────────────────────────

    @Test
    void authorize_success_sameOrg() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        List<Power> delegated = List.of(
                Power.builder().function("ProductOffering").action(List.of("Create", "Update")).build());

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                        payloadWith(OPERATOR_ORG, delegated), "id")
                        .contextWrite(withSecurityContext("t")))
                .verifyComplete();
    }

    @Test
    void authorize_fails_onBehalf_whenOperatorNotTenantAdmin() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_MULTI_ORG);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                        payloadWith(OTHER_ORG, List.of()), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("on-behalf issuance requires TenantAdmin"))
                .verify();
    }

    @Test
    void authorize_fails_onBehalf_whenTenantSimple() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, true, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                        payloadWith(OTHER_ORG, List.of()), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("on-behalf issuance not allowed in tenant of type 'simple'"))
                .verify();
    }

    @Test
    void authorize_success_onBehalf_whenTenantAdmin_andMultiOrg() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, true, PolicyContext.TENANT_TYPE_MULTI_ORG);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG,
                        payloadWith(OTHER_ORG, List.of()), "id")
                        .contextWrite(withSecurityContext("t")))
                .verifyComplete();
    }

    // ─── Machine profile uses the same rule ────────────────────────────────

    @Test
    void authorize_success_machine_sameOrg() {
        when(credentialProfileRegistry.getByConfigurationId(MACHINE_CFG))
                .thenReturn(profileWithRule(MACHINE_CFG, "RequireLearCredentialIssuance"));
        stubPayloadPowerConversion();
        List<Power> opPowers = List.of(Power.builder().function("Onboarding").action("Execute").build());
        PolicyContext ctx = ctx(opPowers, OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(MACHINE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(MACHINE_CFG,
                        payloadWith(OPERATOR_ORG, List.of()), "id")
                        .contextWrite(withSecurityContext("t")))
                .verifyComplete();
    }

    // ─── Certification rule (unchanged) ────────────────────────────────────

    @Test
    void authorize_cert_fails_whenOperatorLacksCertificationAttest() {
        when(credentialProfileRegistry.getByConfigurationId(CERT_CFG))
                .thenReturn(profileWithRule(CERT_CFG, "RequireCertificationIssuance"));
        PolicyContext ctx = ctx(Collections.emptyList(), OPERATOR_ORG, false, false,
                PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(CERT_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(CERT_CFG, mock(JsonNode.class), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectError(InsufficientPermissionException.class)
                .verify();
    }

    @Test
    void authorize_cert_success_whenBothHaveCertificationAttest() throws Exception {
        when(credentialProfileRegistry.getByConfigurationId(CERT_CFG))
                .thenReturn(profileWithRule(CERT_CFG, "RequireCertificationIssuance"));
        List<Power> certPowers = List.of(
                Power.builder().function("Certification").action("Attest").build());
        PolicyContext ctx = ctx(certPowers, OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(CERT_CFG), any()))
                .thenReturn(Mono.just(ctx));

        SignedJWT idJwt = mock(SignedJWT.class);
        Payload idPayload = new Payload(new HashMap<>());
        when(idJwt.getPayload()).thenReturn(idPayload);
        when(verifierService.verifyTokenWithoutExpiration("id")).thenReturn(Mono.empty());
        when(jwtService.parseJWT("id")).thenReturn(idJwt);
        when(jwtService.getClaimFromPayload(idPayload, "vc_json")).thenReturn("\"vcJson\"");
        when(objectMapper.readValue("\"vcJson\"", String.class)).thenReturn("vcJson");
        var idVcNode = realMapper.createObjectNode();
        CredentialProfile idProfile = mock(CredentialProfile.class);
        Power certPower = Power.builder().function("Certification").action("Attest").build();
        var parsed = new DynamicCredentialParser.ParsedCredential(idVcNode, idProfile, EMPLOYEE_CFG);
        when(credentialParser.parse("vcJson")).thenReturn(parsed);
        when(credentialParser.extractPowers(idVcNode, idProfile)).thenReturn(List.of(certPower));

        StepVerifier.create(issuancePdpService.authorize(CERT_CFG, mock(JsonNode.class), "id")
                        .contextWrite(withSecurityContext("t")))
                .verifyComplete();
    }

    // ─── Unknown rule rejected ─────────────────────────────────────────────

    @Test
    void authorize_fails_whenProfileHasUnknownRule() {
        when(credentialProfileRegistry.getByConfigurationId(EMPLOYEE_CFG))
                .thenReturn(profileWithRule(EMPLOYEE_CFG, "UnknownRule"));
        PolicyContext ctx = ctx(List.of(), OPERATOR_ORG, false, false, PolicyContext.TENANT_TYPE_SIMPLE);
        when(policyContextFactory.fromTokenForIssuance(eq("t"), eq(EMPLOYEE_CFG), any()))
                .thenReturn(Mono.just(ctx));

        StepVerifier.create(issuancePdpService.authorize(EMPLOYEE_CFG, mock(JsonNode.class), "id")
                        .contextWrite(withSecurityContext("t")))
                .expectErrorMatches(e -> e instanceof InsufficientPermissionException
                        && e.getMessage().contains("Unknown policy rule: UnknownRule"))
                .verify();
    }
}
