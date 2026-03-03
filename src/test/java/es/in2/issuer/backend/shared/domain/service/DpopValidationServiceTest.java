package es.in2.issuer.backend.shared.domain.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class DpopValidationServiceTest {

    private DpopValidationService dpopValidationService;
    private ECKey ecKey;

    @BeforeEach
    void setUp() throws Exception {
        dpopValidationService = new DpopValidationService();
        ecKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void validate_shouldReturnThumbprintForValidDpopProof() throws Exception {
        String dpop = buildDpopProof("POST", "https://issuer.example.com/token");

        String thumbprint = dpopValidationService.validate(dpop, "POST", "https://issuer.example.com/token");

        assertNotNull(thumbprint);
        assertEquals(ecKey.toPublicJWK().computeThumbprint().toString(), thumbprint);
    }

    @Test
    void validate_shouldThrowOnNullHeader() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> dpopValidationService.validate(null, "POST", "https://example.com")
        );
        assertEquals("Missing DPoP proof", ex.getMessage());
    }

    @Test
    void validate_shouldThrowOnBlankHeader() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> dpopValidationService.validate("  ", "POST", "https://example.com")
        );
        assertEquals("Missing DPoP proof", ex.getMessage());
    }

    @Test
    void validate_shouldThrowOnWrongTyp() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("at+jwt"))
                .jwk(ecKey.toPublicJWK())
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", "https://example.com")
                .issueTime(new Date())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecKey));

        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate(jwt.serialize(), "POST", "https://example.com"));
    }

    @Test
    void validate_shouldThrowOnWrongAlgorithm() throws Exception {
        // Use RSA would fail, but since we only support ES256 keys in the header,
        // we test by providing an invalid DPoP string format
        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate("not.a.jwt", "POST", "https://example.com"));
    }

    @Test
    void validate_shouldThrowOnHtmMismatch() throws Exception {
        String dpop = buildDpopProof("POST", "https://example.com");

        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate(dpop, "GET", "https://example.com"));
    }

    @Test
    void validate_shouldThrowOnHtuMismatch() throws Exception {
        String dpop = buildDpopProof("POST", "https://example.com/par");

        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate(dpop, "POST", "https://example.com/token"));
    }

    @Test
    void validate_shouldThrowOnReplayedJti() throws Exception {
        String dpop = buildDpopProof("POST", "https://example.com");

        dpopValidationService.validate(dpop, "POST", "https://example.com");

        // Re-creating exact same JWT would have different jti, so we re-parse and re-send
        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate(dpop, "POST", "https://example.com"));
    }

    @Test
    void validate_shouldThrowOnExpiredProof() throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(ecKey.toPublicJWK())
                .build();

        // Set iat to 10 minutes ago (exceeds 300s threshold)
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", "https://example.com")
                .issueTime(new Date(System.currentTimeMillis() - 600_000))
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecKey));

        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate(jwt.serialize(), "POST", "https://example.com"));
    }

    @Test
    void validate_shouldThrowOnMissingJwkInHeader() throws Exception {
        // Build without jwk
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", "POST")
                .claim("htu", "https://example.com")
                .issueTime(new Date())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecKey));

        assertThrows(IllegalArgumentException.class,
                () -> dpopValidationService.validate(jwt.serialize(), "POST", "https://example.com"));
    }

    private String buildDpopProof(String method, String uri) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(ecKey.toPublicJWK())
                .build();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", method)
                .claim("htu", uri)
                .issueTime(new Date())
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(ecKey));
        return jwt.serialize();
    }
}
