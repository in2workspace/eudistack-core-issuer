package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.model.port.IssuerProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Point 16: the mandate of the LEAR attestation is read from the token claims, the same for every type. */
class JwtCallerProviderTest {

    private static final byte[] SECRET = "0123456789abcdef0123456789abcdef".getBytes();
    private static final String ORG_PATH = "mandator.organizationIdentifier";

    private final JwtCallerProvider provider = providerReadingOrganizationAt(ORG_PATH);

    private static JwtCallerProvider providerReadingOrganizationAt(String path) {
        IssuerProperties properties = mock(IssuerProperties.class);
        when(properties.getManagementTokenOrgIdJsonPath()).thenReturn(path);
        return new JwtCallerProvider(new ObjectMapper(), properties);
    }

    private static String token(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(SECRET));
        return jwt.serialize();
    }

    private static JWTClaimsSet.Builder claimsOf(String organization) {
        return new JWTClaimsSet.Builder()
                .subject("mandatee@example.com").jwtID("jti-1")
                .claim("mandator", Map.of("organizationIdentifier", organization));
    }

    @Test
    void JwtCallerProvider_fromToken_readsOrganizationPowersTenantAndAttestationFromTheClaims() throws Exception {
        // Given
        String token = token(claimsOf("VATES-A")
                .claim("power", List.of(Map.of("type", "domain", "domain", "sandbox",
                        "function", "Onboarding", "action", List.of("Execute"))))
                .claim("tenant", "sandbox-stg")
                .claim("credential_type", "learcredential.machine.w3c.3")
                .claim("vc", Map.of("id", "urn:uuid:attestation-1"))
                .build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> {
                    assertThat(caller.organizationIdentifier()).isEqualTo("VATES-A");
                    assertThat(caller.powers()).singleElement()
                            .satisfies(p -> assertThat(p.function()).isEqualTo("Onboarding"));
                    assertThat(caller.tokenTenant()).isEqualTo("sandbox");
                    assertThat(caller.credentialType()).isEqualTo("learcredential.machine.w3c.3");
                    assertThat(caller.tokenId()).isEqualTo("jti-1");
                    assertThat(caller.attestationId()).isEqualTo("urn:uuid:attestation-1");
                })
                .verifyComplete();
    }

    /** AC-16: an SD-JWT VC has no id; its status list entry identifies the attestation in the trace. */
    @Test
    void JwtCallerProvider_fromToken_identifiesAnSdJwtAttestationByItsStatusListEntry() throws Exception {
        // Given
        String token = token(claimsOf("VATES-A")
                .claim("vc", Map.of("vct", "learcredential.employee.sd.1", "status", Map.of("status_list",
                        Map.of("uri", "https://sandbox.example/issuer/token/v1/credentials/status/1", "idx", 123764))))
                .build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> assertThat(caller.attestationId())
                        .isEqualTo("https://sandbox.example/issuer/token/v1/credentials/status/1#123764"))
                .verifyComplete();
    }

    @Test
    void JwtCallerProvider_fromToken_neverKeepsTheSubjectEmail() throws Exception {
        // Given
        String token = token(claimsOf("VATES-A").build());

        // When / Then: §10.3 -- the mandatee's email (sub) must not reach the decision trace
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> assertThat(caller.toString()).doesNotContain("mandatee@example.com"))
                .verifyComplete();
    }

    @Test
    void JwtCallerProvider_fromToken_readsTheOrganizationAtTheConfiguredPath() throws Exception {
        // Given
        JwtCallerProvider nested = providerReadingOrganizationAt("vc.credentialSubject.mandate.mandator.organizationIdentifier");
        String token = token(new JWTClaimsSet.Builder()
                .claim("vc", Map.of("credentialSubject", Map.of("mandate",
                        Map.of("mandator", Map.of("organizationIdentifier", "VATES-N")))))
                .build());

        // When / Then
        StepVerifier.create(nested.fromToken(token))
                .assertNext(caller -> assertThat(caller.organizationIdentifier()).isEqualTo("VATES-N"))
                .verifyComplete();
    }

    @Test
    void JwtCallerProvider_fromToken_malformedPowerClaimGivesACallerWithoutPowers() throws Exception {
        // Given
        String token = token(claimsOf("VATES-A").claim("power", "Onboarding").build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> {
                    assertThat(caller.powers()).isEmpty();
                    assertThat(caller.tokenTenant()).isNull();
                    assertThat(caller.attestationId()).isNull();
                })
                .verifyComplete();
    }

    /** A combination of both sets of keys that no rule decided (Jackson resolves each field on its own). */
    @Test
    void JwtCallerProvider_fromToken_aPowerWhoseFieldAndAliasDifferDoesNotCount() throws Exception {
        // Given
        Map<String, Object> crossed = Map.of("type", "zzz", "tmf_type", "organization", "tmf_function", "zzz",
                "function", "Onboarding", "domain", "sandbox", "action", List.of("Execute"));
        Map<String, Object> certify = Map.of("type", "domain", "function", "Certification",
                "domain", "sandbox", "action", List.of("Attest"));
        String token = token(claimsOf("VATES-A").claim("power", List.of(crossed, certify)).build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> assertThat(caller.powers()).singleElement()
                        .satisfies(power -> assertThat(power.function()).isEqualTo("Certification")))
                .verifyComplete();
    }

    /** Jackson would fail on the alias arriving once it has all the fields of the record, and drop every power. */
    @ParameterizedTest
    @ValueSource(strings = {
            "{\"tmf_type\":\"domain\",\"type\":\"domain\",\"function\":\"Certification\",\"domain\":\"sandbox\",\"action\":[\"Attest\"]}",
            "{\"type\":\"domain\",\"function\":\"Certification\",\"domain\":\"sandbox\",\"action\":[\"Attest\"],\"tmf_type\":\"domain\"}"
    })
    void JwtCallerProvider_fromToken_aPowerWithTheSameValueInBothKeysCountsWhateverTheirOrder(String power) throws Exception {
        // Given
        String token = token(claimsOf("VATES-A").claim("power", List.of(JSONObjectUtils.parse(power))).build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> assertThat(caller.powers()).singleElement()
                        .satisfies(granted -> assertThat(granted.type()).isEqualTo("domain")))
                .verifyComplete();
    }

    @Test
    void JwtCallerProvider_fromToken_readsAPowerUnderItsTmfAliases() throws Exception {
        // Given
        String power = "{\"tmf_type\":\"domain\",\"tmf_function\":\"Certification\",\"tmf_domain\":\"sandbox\",\"tmf_action\":[\"Attest\"]}";
        String token = token(claimsOf("VATES-A").claim("power", List.of(JSONObjectUtils.parse(power))).build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .assertNext(caller -> assertThat(caller.powers()).singleElement()
                        .satisfies(granted -> assertThat(granted.function()).isEqualTo("Certification")))
                .verifyComplete();
    }

    @Test
    void JwtCallerProvider_fromToken_rejectsATokenWithoutOrganization() throws Exception {
        // Given
        String token = token(new JWTClaimsSet.Builder().subject("x").build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void JwtCallerProvider_fromToken_rejectsABlankOrganization() throws Exception {
        // Given: a blank organization would match the processes stored with "" (issued before EUD-272)
        String token = token(claimsOf("  ").build());

        // When / Then
        StepVerifier.create(provider.fromToken(token))
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void JwtCallerProvider_fromToken_rejectsAnUnparseableToken() {
        StepVerifier.create(provider.fromToken("not-a-jwt"))
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void JwtCallerProvider_current_readsTheTokenOfTheSecurityContext() throws Exception {
        // Given
        String raw = token(claimsOf("VATES-A").build());
        Jwt jwt = Jwt.withTokenValue(raw).header("alg", "HS256").claim("sub", "x")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();

        // When / Then
        StepVerifier.create(provider.current()
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(new JwtAuthenticationToken(jwt))))
                .assertNext(caller -> assertThat(caller.organizationIdentifier()).isEqualTo("VATES-A"))
                .verifyComplete();
    }

    @Test
    void JwtCallerProvider_current_rejectsAnAuthenticationThatIsNotAJwt() {
        // Given
        TestingAuthenticationToken other = new TestingAuthenticationToken("user", "password");

        // When / Then: an invalid token (401), not a ClassCastException (500)
        StepVerifier.create(provider.current()
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(other)))
                .expectError(InvalidTokenException.class)
                .verify();
    }

    @Test
    void JwtCallerProvider_current_rejectsARequestWithoutAuthentication() {
        StepVerifier.create(provider.current())
                .expectError(InvalidTokenException.class)
                .verify();
    }

    // ---- currentPerson (B1 of the EUD-323 review) ---------------------------------

    private static Jwt accessToken(Map<String, Object> claims) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "ES256")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60));
        claims.forEach(builder::claim);
        return builder.build();
    }

    private StepVerifier.FirstStep<String> personOf(Jwt jwt, String principalName) {
        return StepVerifier.create(provider.currentPerson().contextWrite(
                ReactiveSecurityContextHolder.withAuthentication(
                        new JwtAuthenticationToken(jwt, List.of(), principalName))));
    }

    /** The portal's LEAR SD-JWT access token: the mandatee sits under vc.mandate. */
    @Test
    void JwtCallerProvider_currentPerson_readsTheSdJwtMandateeEmail() {
        Jwt jwt = accessToken(Map.of("sub", "did:key:zHolder",
                "vc", Map.of("mandate", Map.of("mandatee", Map.of("email", "jane@example.org")))));

        personOf(jwt, "anonymous").expectNext("jane@example.org").verifyComplete();
    }

    @Test
    void JwtCallerProvider_currentPerson_readsTheW3cMandateeEmail() {
        Jwt jwt = accessToken(Map.of("sub", "x", "vc", Map.of("credentialSubject",
                Map.of("mandate", Map.of("mandatee", Map.of("emailAddress", "jane@example.org"))))));

        personOf(jwt, "anonymous").expectNext("jane@example.org").verifyComplete();
    }

    /** The principal name may come from an unverified X-ID-Token: it is never what names the person. */
    @Test
    void JwtCallerProvider_currentPerson_ignoresThePrincipalName() {
        Jwt jwt = accessToken(Map.of("sub", "x", "mandatee", Map.of("email", "jane@example.org")));

        personOf(jwt, "someone.else@example.org").expectNext("jane@example.org").verifyComplete();
    }

    /** A machine's token has no mandatee email: its sub (a DID) identifies it. */
    @Test
    void JwtCallerProvider_currentPerson_withoutMandateeEmail_usesTheSubject() {
        personOf(accessToken(Map.of("sub", "did:key:zMachine")), "anonymous")
                .expectNext("did:key:zMachine").verifyComplete();
    }

    @Test
    void JwtCallerProvider_currentPerson_withAnAuthenticationThatIsNotAJwt_isEmpty() {
        StepVerifier.create(provider.currentPerson().contextWrite(ReactiveSecurityContextHolder.withAuthentication(
                        new TestingAuthenticationToken("jane@example.org", "password"))))
                .verifyComplete();
    }
}
