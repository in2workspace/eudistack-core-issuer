package es.in2.issuer.backend.shared.domain.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Point 16: the mandate of the LEAR attestation is read from the token claims, the same for every type. */
class CallerResolverTest {

    private static final byte[] SECRET = "0123456789abcdef0123456789abcdef".getBytes();
    private final CallerResolver resolver = new CallerResolver(new ObjectMapper());

    private static String token(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(SECRET));
        return jwt.serialize();
    }

    @Test
    void readsOrganizationPowersTenantAndAttestationFromTheClaims() throws Exception {
        String token = token(new JWTClaimsSet.Builder()
                .subject("sub-1").jwtID("jti-1")
                .claim("mandator", Map.of("organizationIdentifier", "VATES-A"))
                .claim("power", List.of(Map.of("type", "domain", "domain", "sandbox",
                        "function", "Onboarding", "action", List.of("Execute"))))
                .claim("tenant", "sandbox-stg")
                .claim("credential_type", "learcredential.machine.w3c.3")
                .claim("vc", Map.of("id", "urn:uuid:attestation-1"))
                .build());

        StepVerifier.create(resolver.fromToken(token))
                .assertNext(caller -> {
                    assertThat(caller.organizationIdentifier()).isEqualTo("VATES-A");
                    assertThat(caller.powers()).singleElement()
                            .satisfies(p -> assertThat(p.function()).isEqualTo("Onboarding"));
                    assertThat(caller.tokenTenant()).isEqualTo("sandbox");
                    assertThat(caller.credentialType()).isEqualTo("learcredential.machine.w3c.3");
                    assertThat(caller.subject()).isEqualTo("sub-1");
                    assertThat(caller.tokenId()).isEqualTo("jti-1");
                    assertThat(caller.attestationId()).isEqualTo("urn:uuid:attestation-1");
                })
                .verifyComplete();
    }

    @Test
    void missingOrMalformedClaims_giveACallerWithoutPowers() throws Exception {
        String token = token(new JWTClaimsSet.Builder().subject("x").claim("power", "Onboarding").build());

        StepVerifier.create(resolver.fromToken(token))
                .assertNext(caller -> {
                    assertThat(caller.powers()).isEmpty();
                    assertThat(caller.organizationIdentifier()).isNull();
                    assertThat(caller.tokenTenant()).isNull();
                    assertThat(caller.attestationId()).isNull();
                })
                .verifyComplete();
    }

    @Test
    void unparseableToken_isAnInvalidToken() {
        StepVerifier.create(resolver.fromToken("not-a-jwt"))
                .expectError(InvalidTokenException.class)
                .verify();
    }
}
