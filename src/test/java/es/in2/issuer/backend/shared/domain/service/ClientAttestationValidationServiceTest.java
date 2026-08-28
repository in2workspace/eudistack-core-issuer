package es.in2.issuer.backend.shared.domain.service;

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

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientAttestationValidationServiceTest {

    private static final String WIA_ISSUER = "https://wallet-provider.example.com";
    private static final String ISSUER_URL = "https://issuer.example.com";

    @Mock
    private TrustedWalletProvidersService trustedWalletProvidersService;

    private ClientAttestationValidationService service;
    private ECKey wiaSigningKey;

    @BeforeEach
    void setUp() throws Exception {
        service = new ClientAttestationValidationService(trustedWalletProvidersService, ISSUER_URL);
        wiaSigningKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    @Test
    void validateHeaders_whenWiaMissingSubClaim_throwsInvalidClientAttestation() throws Exception {
        String wia = buildWia(claimsBuilder -> claimsBuilder); // no .subject(...)

        when(trustedWalletProvidersService.isWalletProviderTrusted(WIA_ISSUER)).thenReturn(true);
        when(trustedWalletProvidersService.getAllTrustedProviders()).thenReturn(List.of());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "any-pop", ISSUER_URL));

        assertEquals("Client Attestation JWT missing sub claim", ex.getMessage());
    }

    @Test
    void validateHeaders_whenWiaHasBlankSubClaim_throwsInvalidClientAttestation() throws Exception {
        String wia = buildWia(claimsBuilder -> claimsBuilder.subject("  "));

        when(trustedWalletProvidersService.isWalletProviderTrusted(WIA_ISSUER)).thenReturn(true);
        when(trustedWalletProvidersService.getAllTrustedProviders()).thenReturn(List.of());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "any-pop", ISSUER_URL));

        assertEquals("Client Attestation JWT missing sub claim", ex.getMessage());
    }

    private String buildWia(java.util.function.UnaryOperator<JWTClaimsSet.Builder> claimsCustomizer) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-client-attestation+jwt"))
                .jwk(wiaSigningKey.toPublicJWK())
                .build();

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(WIA_ISSUER)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000));

        JWTClaimsSet claims = claimsCustomizer.apply(builder).build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(wiaSigningKey));
        return jwt.serialize();
    }
}
