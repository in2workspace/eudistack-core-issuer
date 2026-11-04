package es.in2.issuer.backend.shared.domain.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.dto.AccessTokenContext;
import es.in2.issuer.backend.shared.domain.model.enums.UserRole;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import es.in2.issuer.backend.shared.domain.exception.TenantMismatchException;
import es.in2.issuer.backend.shared.domain.policy.service.impl.PowerAuthorizationServiceImpl;
import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.domain.service.TenantCredentialProfileService;
import es.in2.issuer.backend.shared.infrastructure.config.FileAuthorizationMatrixProvider;
import es.in2.issuer.backend.shared.infrastructure.config.security.JwtCallerProvider;
import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises {@link AccessTokenServiceImpl} with real signed JWTs and a real ObjectMapper to cover
 * role resolution, DPoP prefix handling and access-token context branches.
 */
@ExtendWith(MockitoExtension.class)
class AccessTokenServiceImplBranchesTest {

    private static final byte[] HMAC_SECRET = "0123456789abcdef0123456789abcdef".getBytes();
    private static final String ORG_ID_PATH = "mandator.organizationIdentifier";
    private static final String ADMIN_ORG = "VATES-ADMIN";
    private static final String TENANT = "acme";

    @Mock
    private IssuerProperties appConfig;
    @Mock
    private TenantRegistryService tenantRegistryService;

    private AccessTokenServiceImpl service;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        lenient().when(appConfig.getManagementTokenOrgIdJsonPath()).thenReturn(ORG_ID_PATH);
        JwtCallerProvider callerProvider = new JwtCallerProvider(objectMapper, appConfig);
        // The real decision point with the bundled matrix: role resolution is the matrix's recognition.
        PowerAuthorizationServiceImpl pdp = new PowerAuthorizationServiceImpl(
                new FileAuthorizationMatrixProvider("", mock(AuditService.class)), callerProvider,
                mock(TenantCredentialProfileService.class), mock(AuditService.class), objectMapper);
        service = new AccessTokenServiceImpl(objectMapper, appConfig, tenantRegistryService, callerProvider, pdp);
    }

    // --- getCleanBearerToken ---

    @ParameterizedTest
    @CsvSource({
            "Bearer abc, abc",
            "bearer abc, abc",
            "DPoP abc, abc",
            "dpop  abc , abc",
            "Basic abc, Basic abc"
    })
    void getCleanBearerToken_stripsKnownSchemes(String header, String expected) {
        StepVerifier.create(service.getCleanBearerToken(header))
                .expectNext(expected)
                .verifyComplete();
    }

    // --- getAuthorizationContext: role resolution ---

    static Stream<Arguments> roleCases() {
        Map<String, Object> tenantAdminPower = Map.of("type", "organization", "domain", TENANT,
                "function", "Onboarding", "action", List.of("Execute"));
        Map<String, Object> orgAdminPower = Map.of("type", "domain", "domain", TENANT,
                "function", "Onboarding", "action", "Execute");
        return Stream.of(
                Arguments.of(Named.of("platform admin with action array", Map.of(
                        "mandator", Map.of("organizationIdentifier", "ANY"),
                        "power", List.of(Map.of("type", "organization", "domain", "EUDISTACK",
                                "function", "System", "action", List.of("Read", "Administration"))))),
                        UserRole.SYSADMIN),
                Arguments.of(Named.of("organization power from another domain", Map.of(
                        "mandator", Map.of("organizationIdentifier", "OTHER"),
                        "power", List.of(Map.of("type", "organization", "domain", "DOME",
                                "function", "System", "action", "Administration")))),
                        UserRole.USER),
                Arguments.of(Named.of("tenant admin by its power, whatever its organization", Map.of(
                        "mandator", Map.of("organizationIdentifier", "ANY-ORG"),
                        "power", List.of(Map.of("function", "Other", "action", "Execute"), tenantAdminPower))),
                        UserRole.TENANT_ADMIN),
                Arguments.of(Named.of("tenant admin with tmf aliases", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG),
                        "power", List.of(Map.of("tmf_type", "organization", "tmf_domain", TENANT,
                                "tmf_function", "Onboarding", "tmf_action", List.of("Execute"))))),
                        UserRole.TENANT_ADMIN),
                Arguments.of(Named.of("organization admin, even from the former admin organization", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG),
                        "power", List.of(orgAdminPower))),
                        UserRole.LEAR),
                Arguments.of(Named.of("organization admin, domain in another case", Map.of(
                        "mandator", Map.of("organizationIdentifier", "OTHER"),
                        "power", List.of(Map.of("type", "domain", "domain", "ACME",
                                "function", "Onboarding", "action", "Execute")))),
                        UserRole.LEAR),
                Arguments.of(Named.of("power type not in lowercase is not recognized", Map.of(
                        "mandator", Map.of("organizationIdentifier", "OTHER"),
                        "power", List.of(Map.of("type", "Domain", "domain", TENANT,
                                "function", "Onboarding", "action", "Execute")))),
                        UserRole.USER),
                Arguments.of(Named.of("Onboarding power of another tenant", Map.of(
                        "mandator", Map.of("organizationIdentifier", "OTHER"),
                        "power", List.of(Map.of("type", "organization", "domain", "kpmg",
                                "function", "Onboarding", "action", "Execute")))),
                        UserRole.USER),
                Arguments.of(Named.of("without power claim", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG))),
                        UserRole.USER),
                Arguments.of(Named.of("with non-array power", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG),
                        "power", "Onboarding")),
                        UserRole.USER),
                Arguments.of(Named.of("power lacking action", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG),
                        "power", List.of(Map.of("type", "domain", "domain", TENANT, "function", "Onboarding")))),
                        UserRole.USER),
                Arguments.of(Named.of("wrong action", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG),
                        "power", List.of(Map.of("type", "domain", "domain", TENANT,
                                "function", "Onboarding", "action", List.of("Read"))))),
                        UserRole.USER),
                Arguments.of(Named.of("non-text action", Map.of(
                        "mandator", Map.of("organizationIdentifier", ADMIN_ORG),
                        "power", List.of(Map.of("type", "domain", "domain", TENANT,
                                "function", "Onboarding", "action", 42)))),
                        UserRole.USER));
    }

    @ParameterizedTest
    @MethodSource("roleCases")
    void getAuthorizationContext_resolvesRoleFromPowersAlone(Map<String, Object> claims, UserRole expectedRole) throws JOSEException {
        // Arrange
        String token = token(b -> withClaims(b, claims).claim("tenant", TENANT));
        when(tenantRegistryService.getTenantType(TENANT)).thenReturn(Mono.just("STANDARD"));

        // Act + Assert
        StepVerifier.create(service.getAuthorizationContext("Bearer " + token)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .assertNext(ctx -> {
                    assertThat(ctx.role()).isEqualTo(expectedRole);
                    assertThat(ctx.readOnly()).isFalse();
                    assertThat(ctx.tenantType()).isEqualTo("STANDARD");
                })
                .verifyComplete();
    }

    @Test
    void getAuthorizationContext_platformAdminInPlatformTenant_isReadOnly() throws JOSEException {
        String token = token(b -> withClaims(b, Map.of(
                "mandator", Map.of("organizationIdentifier", "ANY"),
                "power", List.of(Map.of("type", "organization", "domain", "EUDISTACK",
                        "function", "System", "action", List.of("Administration")))))
                .claim("tenant", "platform"));
        when(tenantRegistryService.getTenantType("platform")).thenReturn(Mono.just("platform"));

        StepVerifier.create(service.getAuthorizationContext("Bearer " + token)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "platform")))
                .assertNext(ctx -> {
                    assertThat(ctx.role()).isEqualTo(UserRole.SYSADMIN);
                    assertThat(ctx.readOnly()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void getAuthorizationContext_withoutMandator_isAnInvalidToken() throws JOSEException {
        // Given: a token that represents no organization is not a caller of the management API
        String token = token(b -> withClaims(b, Map.of("sub", "x")).claim("tenant", TENANT));

        // When / Then: 401, not a context with a null organization (500 further down)
        StepVerifier.create(service.getAuthorizationContext("Bearer " + token)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(InvalidTokenException.class)
                .verify();
    }

    /** FR-02 / S3 of the EUD-272 security review: the role is never resolved for a token of another tenant. */
    @Test
    void getAuthorizationContext_withATokenOfAnotherTenant_failsAsTenantMismatch() throws JOSEException {
        // Given: a platform administrator's token issued for the platform tenant, used on another tenant
        String token = token(b -> withClaims(b, Map.of(
                "mandator", Map.of("organizationIdentifier", "ANY"),
                "power", List.of(Map.of("type", "organization", "domain", "EUDISTACK",
                        "function", "System", "action", List.of("Administration")))))
                .claim("tenant", "platform"));

        // When / Then: it would otherwise act there without the platform tenant's read-only mode
        StepVerifier.create(service.getAuthorizationContext("Bearer " + token)
                        .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)))
                .expectError(TenantMismatchException.class)
                .verify();
    }

    @Test
    void getAuthorizationContext_whenTokenUnparseable_errorsInvalidToken() {
        StepVerifier.create(service.getAuthorizationContext("Bearer not-a-jwt"))
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void getAuthorizationContext_withoutTenantInContext_failsClosed() throws JOSEException {
        String token = token(b -> withClaims(b, Map.of("mandator", Map.of("organizationIdentifier", "OTHER"))));

        StepVerifier.create(service.getAuthorizationContext("Bearer " + token))
                .expectError(TenantMismatchException.class)
                .verify();
    }

    // --- getOrganizationId ---

    @Test
    void getOrganizationId_withDpopHeader_returnsOrgId() throws JOSEException {
        String token = token(b -> withClaims(b, Map.of("mandator", Map.of("organizationIdentifier", "VATES-1"))));

        StepVerifier.create(service.getOrganizationId("DPoP " + token))
                .expectNext("VATES-1")
                .verifyComplete();
    }

    @Test
    void getOrganizationId_whenOrgIdMissing_errorsInvalidToken() throws JOSEException {
        String token = token(b -> b.subject("x"));

        StepVerifier.create(service.getOrganizationId("Bearer " + token))
                .expectErrorSatisfies(e -> assertThat(e).hasMessageContaining(ORG_ID_PATH))
                .verify();
    }

    // --- getTokenTenant ---

    @Test
    void getTokenTenant_whenTenantClaimNull_completesEmpty() throws JOSEException {
        String token = token(b -> b.claim("tenant", null).claim("mandator", Map.of()));

        StepVerifier.create(service.getTokenTenant("Bearer " + token))
                .verifyComplete();
    }

    // --- resolveAccessTokenContext ---

    static Stream<Arguments> cnfClaims() {
        return Stream.of(
                Arguments.of(Named.of("cnf with jkt", Map.of("jkt", "thumb-123")), "thumb-123"),
                Arguments.of(Named.of("cnf with non-string jkt", Map.of("jkt", 5)), null),
                Arguments.of(Named.of("cnf without jkt", Map.of("kid", "k1")), null),
                Arguments.of(Named.of("cnf not an object", "plain"), null));
    }

    @ParameterizedTest
    @MethodSource("cnfClaims")
    void resolveAccessTokenContext_extractsCnfJkt(Object cnf, String expectedJkt) throws JOSEException {
        String token = token(b -> validAccessToken(b).claim("cnf", cnf));

        StepVerifier.create(service.resolveAccessTokenContext("DPoP " + token))
                .assertNext(ctx -> {
                    assertThat(ctx.jti()).isEqualTo("jti-1");
                    assertThat(ctx.issuanceId()).isEqualTo("pid-1");
                    assertThat(ctx.cnfJkt()).isEqualTo(expectedJkt);
                })
                .verifyComplete();
    }

    @Test
    void resolveAccessTokenContext_withoutCnf_returnsNullJkt() throws JOSEException {
        String token = token(this::validAccessToken);

        StepVerifier.create(service.resolveAccessTokenContext("Bearer " + token))
                .assertNext(ctx -> assertThat(ctx).extracting(AccessTokenContext::cnfJkt).isNull())
                .verifyComplete();
    }

    static Stream<Arguments> invalidAccessTokens() {
        return Stream.of(
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.jwtID(" "), "Access token without jti"),
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.claim("pid", " "), "Access token without pid"));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("invalidAccessTokens")
    void resolveAccessTokenContext_withBlankRequiredClaim_errors(UnaryOperator<JWTClaimsSet.Builder> mutation,
                                                                 String expectedMessage) throws JOSEException {
        String token = token(b -> mutation.apply(validAccessToken(b)));

        StepVerifier.create(service.resolveAccessTokenContext("Bearer " + token))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(InvalidTokenException.class)
                        .hasMessage(expectedMessage))
                .verify();
    }

    @Test
    void resolveAccessTokenContext_whenTokenUnparseable_errors() {
        StepVerifier.create(service.resolveAccessTokenContext("Bearer not-a-jws"))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(InvalidTokenException.class)
                        .hasMessage("Error parsing access token"))
                .verify();
    }

    // --- helpers ---

    private JWTClaimsSet.Builder validAccessToken(JWTClaimsSet.Builder builder) {
        return builder.jwtID("jti-1")
                .claim("pid", "pid-1")
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
    }

    private static JWTClaimsSet.Builder withClaims(JWTClaimsSet.Builder builder, Map<String, Object> claims) {
        claims.forEach(builder::claim);
        return builder;
    }

    private static String token(UnaryOperator<JWTClaimsSet.Builder> claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.apply(new JWTClaimsSet.Builder()).build());
        jwt.sign(new MACSigner(HMAC_SECRET));
        return jwt.serialize();
    }
}
