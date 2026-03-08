package es.in2.issuer.backend.shared.domain.policy.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;
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
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssuancePdpServiceImplIntegrationTest {

    private static final String ADMIN_ORG_ID = "IN2_ADMIN_ORG_ID_FOR_TEST";

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
                credentialParser,
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

    @Test
    void authorize_success_for_LearCredentialEmployee_with_realToken() throws Exception {
        when(credentialProfileRegistry.getByConfigurationId("learcredential.employee.w3c.4"))
                .thenReturn(CredentialProfile.builder()
                        .credentialConfigurationId("learcredential.employee.w3c.4")
                        .issuancePolicy(CredentialProfile.IssuancePolicy.builder()
                                .rules(List.of("RequireSignerIssuance", "RequireMandatorDelegation"))
                                .delegationFunction("ProductOffering")
                                .build())
                        .build());

        String token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6d1F2WkVIbXZrMWVPNG5BX0Y4N3lJOVRDa1QxX1FTWHF3X3VUTXZRd2lBIn0.eyJleHAiOjE3NjQzMzI1MzksImlhdCI6MTc2NDMzMjIzOSwiYXV0aF90aW1lIjoxNzY0MzI3MDkwLCJqdGkiOiI5ZmM5ZGZmOS0wNzQwLTQzMDgtOTgwZC1lYjEwMjg1Yzg1NjIiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmRvbWUtbWFya2V0cGxhY2Utc2J4Lm9yZy9yZWFsbXMvZG9tZS1pc3N1ZXIiLCJzdWIiOiI3ZjI4YzJkZi0zMzI3LTQzOTUtODM4OC00NjhmOWEzMWFhNDQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ2Yy1hdXRoLWNsaWVudCIsIm5vbmNlIjoiYzEwOTBmZmFlMDBmNmE2ODU1YzczOWQ0MjliMmM5YTVhNGY0MHNXRVQiLCJzZXNzaW9uX3N0YXRlIjoiMmI4NjA5NGItMmU5Mi00YTk2LTllODEtZmVkYmY1NDg3NDBiIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwczovL2lzc3Vlci5kb21lLW1hcmtldHBsYWNlLXNieC5vcmciXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtZG9tZS1pc3N1ZXIiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBvZmZsaW5lX2FjY2VzcyBwcm9maWxlIiwic2lkIjoiMmI4NjA5NGItMmU5Mi00YTk2LTllODEtZmVkYmY1NDg3NDBiIiwiY29tbW9uTmFtZSI6Ikplc3VzIFJ1aXoiLCJjb3VudHJ5IjoiRVMiLCJyb2xlIjoiTEVBUiIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJzZXJpYWxOdW1iZXIiOiI1NjU2NTY1NlAiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1cm46dXVpZDo5ZDNiNGZkMi05N2JjLTRhZjAtOTBiMC1jZGEyNjRiOTI0ODAiLCJnaXZlbl9uYW1lIjoidGVzdCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsImh0dHBzOi8vY3JlZGVudGlhbHMuZXVkaXN0YWNrLmV1Ly53ZWxsLWtub3duL2NyZWRlbnRpYWxzL2xlYXJfY3JlZGVudGlhbF9lbXBsb3llZS93M2MvdjMiXSwiY3JlZGVudGlhbFN0YXR1cyI6eyJpZCI6Imh0dHBzOi8vaXNzdWVyLmRvbWUtbWFya2V0cGxhY2Utc2J4Lm9yZy9iYWNrb2ZmaWNlL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy8xI203QlJGZ0VrVGNTUmRJYW9hUmpmT2ciLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOi8vaXNzdWVyLmRvbWUtbWFya2V0cGxhY2Utc2J4Lm9yZy9iYWNrb2ZmaWNlL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy8xIiwic3RhdHVzTGlzdEluZGV4IjoibTdCUkZnRWtUY1NSZElhb2FSamZPZyIsInN0YXR1c1B1cnBvc2UiOiJyZXZvY2F0aW9uIiwidHlwZSI6IlBsYWluTGlzdEVudGl0eSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJtYW5kYXRlIjp7Im1hbmRhdGVlIjp7ImVtYWlsIjoibWlndWVsLm1pckBpbjIuZXMiLCJmaXJzdE5hbWUiOiJ0ZXN0IiwiaWQiOiJkaWQ6a2V5OnpEbmFleE55ZjY3MjM0YVE5Nkt0cUtLc3NabnlXcXJaelFrcFZMRkpYNFo1NnZCbTkiLCJsYXN0TmFtZSI6InRlc3QifSwibWFuZGF0b3IiOnsiY29tbW9uTmFtZSI6Ikplc3VzIFJ1aXoiLCJjb3VudHJ5IjoiRVMiLCJlbWFpbCI6Implc3VzLnJ1aXpAaW4yLmVzIiwiaWQiOiJkaWQ6ZWxzaTpWQVRFUy1CNjA2NDU5MDAiLCJvcmdhbml6YXRpb24iOiJJTjIgSU5HRU5JRVJJQSBERSBMQSBJTkZPUk1BQ0lPTiBTT0NJRURBRCBMSU1JVEFEQSIsIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1CNjA2NDU5MDAiLCJzZXJpYWxOdW1iZXIiOiI1NjU2NTY1NlAifSwicG93ZXIiOlt7ImFjdGlvbiI6WyJFeGVjdXRlIl0sImRvbWFpbiI6IkRPTUUiLCJmdW5jdGlvbiI6Ik9uYm9hcmRpbmciLCJ0eXBlIjoiZG9tYWluIn1dfX0sImRlc2NyaXB0aW9uIjoiVmVyaWZpYWJsZSBDcmVkZW50aWFsIGZvciBlbXBsb3llZXMgb2YgYW4gb3JnYW5pemF0aW9uIiwiaWQiOiJ1cm46dXVpZDo5ZDNiNGZkMi05N2JjLTRhZjAtOTBiMC1jZGEyNjRiOTI0ODAiLCJpc3N1ZXIiOnsiY29tbW9uTmFtZSI6IlNlYWwgU2lnbmF0dXJlIENyZWRlbnRpYWxzIGluIFNCWCBmb3IgdGVzdGluZyIsImNvdW50cnkiOiJFUyIsImlkIjoiZGlkOmVsc2k6VkFURVMtQjYwNjQ1OTAwIiwib3JnYW5pemF0aW9uIjoiSU4yIiwib3JnYW5pemF0aW9uSWRlbnRpZmllciI6IlZBVEVTLUI2MDY0NTkwMCIsInNlcmlhbE51bWJlciI6IkI0NzQ0NzU2MCJ9LCJ0eXBlIjpbIkxFQVJDcmVkZW50aWFsRW1wbG95ZWUiLCJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJ2YWxpZEZyb20iOiIyMDI1LTExLTI4VDEwOjE4OjUxLjc3ODg4Mjg3OFoiLCJ2YWxpZFVudGlsIjoiMjAyNi0xMS0yOFQxMDoxODo1MS43Nzg4ODI4NzhaIn0sIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1CNjA2NDU5MDAiLCJvcmdhbml6YXRpb24iOiJJTjIgSU5HRU5JRVJJQSBERSBMQSBJTkZPUk1BQ0lPTiBTT0NJRURBRCBMSU1JVEFEQSIsIm5hbWUiOiJ0ZXN0IHRlc3QiLCJmYW1pbHlfbmFtZSI6InRlc3QiLCJlbWFpbCI6Im1pZ3VlbC5taXJAaW4yLmVzIn0.HTrFfOUmdi1ZqrdsqLTDAxUsamr_GD5dcNK_IfOuwK5mHUqGMIugtD5GZB9IUbUZBVjvd0VmwX0-mSNaaUP4JnbzpAQAuBzvOUlJq0vLeWS0TPOWmr0XkotknfsO3U3CQPBmlwgH5tLqaaeLiNxOC_xX9_scXwnltTxnaV5v92OjdiBGIsTyNdckUG4PJUn2gQdRPWGY5KOGrkaraahMnmAP3nKKSYRHbEGX0Hja6Y5ylmC61JyNZR0lf9kK7MQTrsno6TOqFIaqTF7NzKYrfhleMlCh0uxSNVwJ5sQH9IfPz3MbAhleleMEfjKb1DF7aKPHFZMOO116JBEwKrrL8A";
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
        List<Power> signerPowers = List.of(
                Power.builder().function("Onboarding").action("Execute").domain("DOME").type("Domain").build(),
                Power.builder().function("ProductOffering").action(List.of("Create", "Update")).domain("DOME").type("Domain").build()
        );
        com.fasterxml.jackson.databind.node.ObjectNode vcNode = objectMapper.createObjectNode();
        es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile profile =
                org.mockito.Mockito.mock(es.in2.issuer.backend.shared.domain.model.dto.credential.profile.CredentialProfile.class);
        var parsed = new DynamicCredentialParser.ParsedCredential(vcNode, profile, "learcredential.employee.w3c.4");
        when(credentialParser.parse(any())).thenReturn(parsed);
        when(credentialParser.extractPowers(eq(vcNode), eq(profile)))
                .thenReturn(signerPowers);
        when(credentialParser.extractOrganizationId(eq(vcNode), eq(profile)))
                .thenReturn("VATES-B60645900");

        StepVerifier.create(
                        issuancePdpService.authorize("learcredential.employee.w3c.4", jsonNode, "dummy-id-token")
                                .contextWrite(withSecurityContext(token)))
                .verifyComplete();
    }
}
