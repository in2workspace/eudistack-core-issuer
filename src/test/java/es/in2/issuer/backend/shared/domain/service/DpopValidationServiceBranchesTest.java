package es.in2.issuer.backend.shared.domain.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;

/**
 * Covers the typ/alg/signature/iat/jti/ath branches of {@link DpopValidationService} not exercised by
 * {@link DpopValidationServiceTest}.
 */
@ExtendWith(MockitoExtension.class)
class DpopValidationServiceBranchesTest {

    private static final String HTM = "POST";
    private static final String HTU = "https://issuer.example.com/credential";
    private static final String ACCESS_TOKEN = "eyJhbGciOiJFUzI1NiJ9.access.token";

    @Mock
    private AuditService auditService;

    private DpopValidationService service;
    private ECKey ecKey;

    @BeforeEach
    void setUp() throws JOSEException {
        service = new DpopValidationService(auditService);
        ecKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void validate_whenTypMissing_throws() throws JOSEException {
        // Arrange
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).jwk(ecKey.toPublicJWK()).build();
        String dpop = sign(header, ecKey, b -> b);

        // Act + Assert
        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP typ must be dpop+jwt");
    }

    @Test
    void validate_whenAlgorithmNotEs256_throws() throws JOSEException {
        // Arrange
        ECKey p384 = new ECKeyGenerator(Curve.P_384).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(p384.toPublicJWK())
                .build();
        String dpop = sign(header, p384, b -> b);

        // Act + Assert
        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP must use ES256");
    }

    @Test
    void validate_whenSignedWithDifferentKey_throwsSignatureInvalid() throws JOSEException {
        // Arrange: header advertises ecKey but proof is signed by another key
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        String dpop = sign(dpopHeader(), otherKey, b -> b);

        // Act + Assert
        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP signature invalid");
    }

    @Test
    void validate_whenIatMissing_throws() throws JOSEException {
        String dpop = sign(dpopHeader(), ecKey, b -> b.issueTime(null));

        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP missing iat claim");
    }

    @Test
    void validate_whenJtiMissing_auditsAndThrowsReplay() throws JOSEException {
        // Arrange
        String dpop = sign(dpopHeader(), ecKey, b -> b.jwtID(null));

        // Act + Assert
        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP jti replay detected");
        verify(auditService).auditFailure(eq("dpop.replay.detected"), isNull(), eq("jti replay: null"), any());
    }

    @Test
    void validate_withAccessTokenAndMatchingAth_returnsThumbprint() throws Exception {
        // Arrange
        String ath = ath(ACCESS_TOKEN);
        String dpop = sign(dpopHeader(), ecKey, b -> b.claim("ath", ath));

        // Act
        String jkt = service.validate(dpop, HTM, HTU, ACCESS_TOKEN);

        // Assert
        assertThat(jkt).isEqualTo(ecKey.toPublicJWK().computeThumbprint().toString());
    }

    @Test
    void validate_withAccessTokenButNoAth_throws() throws JOSEException {
        String dpop = sign(dpopHeader(), ecKey, b -> b);

        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU, ACCESS_TOKEN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP missing ath claim for token-bound proof");
    }

    @Test
    void validate_withAccessTokenAndWrongAth_throws() throws Exception {
        String wrongAth = ath("another-token");
        String dpop = sign(dpopHeader(), ecKey, b -> b.claim("ath", wrongAth));

        assertThatThrownBy(() -> service.validate(dpop, HTM, HTU, ACCESS_TOKEN))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("DPoP ath mismatch");
    }

    // --- helpers ---

    private JWSHeader dpopHeader() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(ecKey.toPublicJWK())
                .build();
    }

    private static String sign(JWSHeader header, ECKey signer, UnaryOperator<JWTClaimsSet.Builder> customizer)
            throws JOSEException {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .claim("htm", HTM)
                .claim("htu", HTU)
                .issueTime(new Date());
        SignedJWT jwt = new SignedJWT(header, customizer.apply(claims).build());
        jwt.sign(new ECDSASigner(signer));
        return jwt.serialize();
    }

    private static String ath(String accessToken) throws NoSuchAlgorithmException {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
}
