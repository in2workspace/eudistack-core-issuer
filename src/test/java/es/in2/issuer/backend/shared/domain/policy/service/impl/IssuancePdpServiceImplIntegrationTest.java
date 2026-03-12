package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile;
import es.in2.issuer.backend.shared.domain.policy.PolicyContextFactory;
import es.in2.issuer.backend.shared.domain.policy.PolicyEnforcer;
import es.in2.issuer.backend.shared.domain.policy.rules.RequireCertificationIssuanceRule;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.service.VerifierService;
import es.in2.issuer.backend.shared.domain.service.impl.JWTServiceImpl;
import es.in2.issuer.backend.shared.domain.util.DynamicCredentialParser;
import es.in2.issuer.backend.shared.infrastructure.config.AppConfig;
import es.in2.issuer.backend.shared.infrastructure.config.CredentialProfileRegistry;
import es.in2.issuer.backend.shared.infrastructure.crypto.CryptoComponent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuancePdpServiceImplIntegrationTest {

    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";
    private static final String CREDENTIAL_TYPE = "learcredential.employee.w3c.4";

    private JWTService jwtService;

    @Mock
    private CryptoComponent cryptoComponent;

    private ObjectMapper objectMapper;

    @Mock
    private VerifierService verifierService;

    @Mock
    private AppConfig appConfig;

    @Mock
    private DynamicCredentialParser credentialParser;
    @Mock
    private CredentialProfileRegistry credentialProfileRegistry;
    @Mock
    private AuditService auditService;

    private IssuancePdpServiceImpl issuancePdpService;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        jwtService = new JWTServiceImpl(objectMapper, cryptoComponent);

        org.mockito.Mockito.lenient()
                .when(appConfig.getAdminOrganizationId())
                .thenReturn(ADMIN_ORG_ID);

        PolicyContextFactory policyContextFactory = new PolicyContextFactory(
                jwtService,
                objectMapper,
                appConfig,
                credentialProfileRegistry
        );

        PolicyEnforcer policyEnforcer = new PolicyEnforcer();

        RequireCertificationIssuanceRule certificationRule = new RequireCertificationIssuanceRule(
                verifierService, jwtService, objectMapper, credentialParser);

        issuancePdpService = new IssuancePdpServiceImpl(
                policyContextFactory,
                policyEnforcer,
                objectMapper,
                certificationRule,
                credentialProfileRegistry,
                credentialParser,
                auditService
        );
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

    /**
     * Builds a JWS-like token with flat claims matching the Verifier's access token structure.
     * Constructs compact serialization manually (header.payload.signature) with a dummy signature
     * so that SignedJWT.parse() can parse it without requiring actual signing.
     */
    private String buildFlatClaimsToken(String credentialType, String orgId, List<Map<String, Object>> powers) throws Exception {
        ObjectNode payloadNode = objectMapper.createObjectNode();
        payloadNode.put("credential_type", credentialType);
        payloadNode.put("sub", "test-user");
        payloadNode.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());
        payloadNode.put("iat", Instant.now().getEpochSecond());

        ObjectNode mandatorNode = objectMapper.createObjectNode();
        mandatorNode.put("organizationIdentifier", orgId);
        mandatorNode.put("organization", "IN2 INGENIERIA DE LA INFORMACION SOCIEDAD LIMITADA");
        mandatorNode.put("commonName", "Jesus Ruiz");
        mandatorNode.put("country", "ES");
        mandatorNode.put("email", "jesus.ruiz@in2.es");
        payloadNode.set("mandator", mandatorNode);

        ObjectNode mandateeNode = objectMapper.createObjectNode();
        mandateeNode.put("email", "example@in2.es");
        mandateeNode.put("firstName", "Jhon");
        mandateeNode.put("lastName", "Doe");
        payloadNode.set("mandatee", mandateeNode);

        payloadNode.set("power", objectMapper.valueToTree(powers));

        // Build compact JWS serialization manually: base64url(header).base64url(payload).base64url(signature)
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString("{\"alg\":\"RS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString(payloadNode.toString().getBytes(StandardCharsets.UTF_8));
        String signature = encoder.encodeToString("dummy-signature".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + signature;
    }

    @Test
    void authorize_success_for_LearCredentialEmployee_with_flatToken() throws Exception {
        // Profile for the emitter credential type (used by PolicyContextFactory.resolveProfile)
        when(credentialProfileRegistry.getByConfigurationId(CREDENTIAL_TYPE))
                .thenReturn(CredentialProfile.builder()
                        .credentialConfigurationId(CREDENTIAL_TYPE)
                        .policyExtraction(CredentialProfile.PolicyExtraction.builder()
                                .powersPath("power")
                                .mandatorPath("mandator")
                                .orgIdField("organizationIdentifier")
                                .build())
                        .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                                .rules(List.of("RequireSignerIssuance", "RequireMandatorDelegation"))
                                .delegationFunction("ProductOffering")
                                .build())
                        .build());

        List<Map<String, Object>> powers = List.of(
                Map.of("function", "Onboarding", "action", List.of("Execute"), "domain", "DOME", "type", "Domain"),
                Map.of("function", "ProductOffering", "action", List.of("Create", "Update"), "domain", "DOME", "type", "Domain")
        );

        String token = buildFlatClaimsToken(CREDENTIAL_TYPE, "VATES-B60645900", powers);

        String json = """
                {
                    "life_span": {
                        "end_date_time": "2025-04-02 09:23:22.637345122 +0000 UTC",
                        "start_date_time": "2024-04-02 09:23:22.637345122 +0000 UTC"
                    },
                    "mandatee": {
                        "email": "example@in2.es",
                        "firstName": "Jhon",
                        "lastName": "Doe",
                        "mobile_phone": "+34666336699"
                    },
                    "mandator": {
                        "commonName": "IN2",
                        "country": "ES",
                        "email": "rrhh@in2.es",
                        "organization": "IN2, Ingeniería de la Información, S.L.",
                        "organizationIdentifier": "VATES-B60645900",
                        "serialNumber": "3424320"
                    },
                    "power": [
                        {
                            "id": "ad9b1509-60ea-47d4-9878-18b581d8e19b",
                            "tmf_action": [
                                "Create",
                                "Update"
                            ],
                            "tmf_domain": "DOME",
                            "tmf_function": "ProductOffering",
                            "tmf_type": "Domain"
                        }
                    ]
                }
                """;
        JsonNode jsonNode = objectMapper.readTree(json);

        // RequireMandatorDelegationRule uses credentialParser.extractOrganizationId on the PolicyContext credential
        when(credentialParser.extractOrganizationId(any(), any())).thenReturn("VATES-B60645900");

        StepVerifier.create(
                        issuancePdpService.authorize(CREDENTIAL_TYPE, jsonNode, "dummy-id-token")
                                .contextWrite(withSecurityContext(token)))
                .verifyComplete();
    }
}
