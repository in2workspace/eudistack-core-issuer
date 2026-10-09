package es.in2.issuer.backend.shared.domain.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.service.TrustedWalletProvidersService.TrustedProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientAttestationValidationServiceTest {

    private static final String WIA_ISSUER = "https://wallet-provider.example.com";
    private static final String ISSUER_URL = "https://issuer.example.com";
    private static final String CLIENT_ID = "wallet-client-123";

    @Mock
    private TrustedWalletProvidersService trustedWalletProvidersService;

    private ClientAttestationValidationService service;
    private ECKey wiaSigningKey;
    private ECKey popKey;

    @BeforeEach
    void setUp() throws JOSEException {
        service = new ClientAttestationValidationService(trustedWalletProvidersService, ISSUER_URL);
        wiaSigningKey = new ECKeyGenerator(Curve.P_256).generate();
        popKey = new ECKeyGenerator(Curve.P_256).generate();
    }

    // --- header presence ---

    static Stream<Arguments> missingHeaders() {
        return Stream.of(
                Arguments.of(null, "pop", ClientAttestationValidationService.HEADER_CLIENT_ATTESTATION),
                Arguments.of("  ", "pop", ClientAttestationValidationService.HEADER_CLIENT_ATTESTATION),
                Arguments.of("wia", null, ClientAttestationValidationService.HEADER_CLIENT_ATTESTATION_POP),
                Arguments.of("wia", " ", ClientAttestationValidationService.HEADER_CLIENT_ATTESTATION_POP));
    }

    @ParameterizedTest
    @MethodSource("missingHeaders")
    void validateHeaders_whenHeaderMissing_throwsMissingHeader(String wia, String pop, String expectedHeader) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals("Missing " + expectedHeader + " header", ex.getMessage());
    }

    // --- happy paths ---

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", ISSUER_URL})
    void validateHeaders_withHeaderJwkAndCnfJwk_returnsClientId(String audienceUrl) throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, audienceUrl));
    }

    @Test
    void validateHeaders_whenNoIssuerUrlConfigured_skipsAudienceCheck() throws JOSEException {
        service = new ClientAttestationValidationService(trustedWalletProvidersService, "");
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b.audience((String) null));

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, null));
    }

    @Test
    void validateHeaders_withTrustedEcPem_verifiesAgainstConfiguredKey() throws JOSEException {
        trustIssuer(List.of(
                new TrustedProvider("other", "Other", "irrelevant"),
                new TrustedProvider(WIA_ISSUER, "Blank", " "),
                new TrustedProvider(WIA_ISSUER, "Wallet", toPem(wiaSigningKey.toPublicKey()))));
        String wia = buildWia(null, b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, ISSUER_URL));
    }

    @Test
    void validateHeaders_withTrustedRsaPem_verifiesAgainstConfiguredKey() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048).generate();
        trustIssuer(List.of(new TrustedProvider(WIA_ISSUER, "Wallet", toPem(rsaKey.toPublicKey()))));

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("oauth-client-attestation+jwt"))
                .build();
        SignedJWT wiaJwt = new SignedJWT(header, baseWiaClaims()
                .subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)).build());
        wiaJwt.sign(new RSASSASigner(rsaKey));
        String pop = buildPop(popKey, b -> b);

        assertEquals(CLIENT_ID, service.validateHeaders(wiaJwt.serialize(), pop, ISSUER_URL));
    }

    @Test
    void validateHeaders_withNullPemProvider_fallsBackToHeaderJwk() throws JOSEException {
        trustIssuer(List.of(new TrustedProvider(WIA_ISSUER, "Wallet", null)));
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, ISSUER_URL));
    }

    @Test
    void validateHeaders_withX5cHeader_verifiesAgainstCertificateKey() throws Exception {
        trustIssuer(List.of());
        X509Certificate cert = selfSignedCert(wiaSigningKey);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-client-attestation+jwt"))
                .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
                .build();
        String wia = sign(header, baseWiaClaims().subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)).build());
        String pop = buildPop(popKey, b -> b);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, ISSUER_URL));
    }

    @Test
    void validateHeaders_whenWiaWithoutExp_isAccepted() throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).expirationTime(null).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, ISSUER_URL));
    }

    @Test
    void validateHeaders_withCnfJktMatchingPopHeaderJwk_returnsClientId() throws JOSEException {
        trustIssuer(List.of());
        String jkt = popKey.toPublicJWK().computeThumbprint().toString();
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", Map.of("jkt", jkt)));
        String pop = buildPopWithHeaderJwk(popKey);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, ISSUER_URL));
    }

    @Test
    void validateHeaders_whenPopWithoutJti_isAcceptedRepeatedly() throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b.jwtID(null));
        service.validateHeaders(wia, pop, ISSUER_URL);

        assertEquals(CLIENT_ID, service.validateHeaders(wia, pop, ISSUER_URL));
    }

    // --- WIA failures ---

    @Test
    void validateHeaders_withoutAnyWiaKey_throwsNoKeyAvailable() throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(null, b -> b.subject(CLIENT_ID));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "pop", ISSUER_URL));
        assertThat(ex.getMessage()).contains("no trusted key, x5c or jwk available");
    }

    @Test
    void validateHeaders_whenIssuerNotTrusted_throws() throws JOSEException {
        when(trustedWalletProvidersService.isWalletProviderTrusted(WIA_ISSUER)).thenReturn(false);
        String wia = buildWia(b -> b.subject(CLIENT_ID));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "pop", ISSUER_URL));
        assertThat(ex.getMessage()).contains("not a trusted wallet provider");
    }

    @Test
    void validateHeaders_whenWiaSignedByOtherKey_throwsSignatureFailed() throws JOSEException {
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        trustIssuer(List.of(new TrustedProvider(WIA_ISSUER, "Wallet", toPem(otherKey.toPublicKey()))));
        String wia = buildWia(b -> b.subject(CLIENT_ID));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "pop", ISSUER_URL));
        assertEquals("Client Attestation JWT signature verification failed", ex.getMessage());
    }

    @Test
    void validateHeaders_whenWiaExpired_throws() throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).expirationTime(new Date(System.currentTimeMillis() - 10_000)));

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "pop", ISSUER_URL));
        assertEquals("Client Attestation JWT has expired", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = "  ")
    void validateHeaders_whenWiaSubMissingOrBlank_throwsMissingSub(String subject) throws JOSEException {
        String wia = buildWia(b -> b.subject(subject));
        trustIssuer(List.of());

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, "any-pop", ISSUER_URL));

        assertEquals("Client Attestation JWT missing sub claim", ex.getMessage());
    }

    @Test
    void validateHeaders_whenWiaMalformed_wrapsParseException() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders("not-a-jwt", "pop", ISSUER_URL));
        assertThat(ex.getMessage()).startsWith("Invalid client attestation:");
    }

    // --- cnf key resolution ---

    static Stream<Arguments> unresolvableCnf() {
        return Stream.of(
                Arguments.of(Named.of("no cnf", null)),
                Arguments.of(Named.of("cnf without jwk or jkt", Map.of("kid", "x"))),
                Arguments.of(Named.of("cnf with invalid jwk", Map.of("jwk", Map.of("kty", "bogus")))),
                Arguments.of(Named.of("cnf jkt without PoP header jwk", Map.of("jkt", "abc"))));
    }

    @ParameterizedTest
    @MethodSource("unresolvableCnf")
    void validateHeaders_whenCnfKeyCannotBeResolved_throwsMissingCnf(Map<String, Object> cnf) throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnf));
        String pop = buildPop(popKey, b -> b);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals("WIA missing cnf key for PoP verification", ex.getMessage());
    }

    @Test
    void validateHeaders_withCnfJktNotMatchingPopHeaderJwk_throws() throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", Map.of("jkt", "wrong-thumbprint")));
        String pop = buildPopWithHeaderJwk(popKey);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals("PoP key thumbprint does not match WIA cnf.jkt", ex.getMessage());
    }

    @Test
    void validateHeaders_whenCnfJwkIsSymmetric_throwsAsymmetricRequired() throws JOSEException {
        trustIssuer(List.of());
        OctetSequenceKey hmac = new OctetSequenceKeyGenerator(256).generate();
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", Map.of("jwk", hmac.toJSONObject())));
        String pop = buildPop(popKey, b -> b);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals("cnf key must be an asymmetric key", ex.getMessage());
    }

    // --- PoP failures ---

    @Test
    void validateHeaders_whenPopSignedByOtherKey_throws() throws JOSEException {
        trustIssuer(List.of());
        ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(otherKey, b -> b);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals("PoP signature verification failed", ex.getMessage());
    }

    static Stream<Arguments> invalidPopClaims() {
        long now = System.currentTimeMillis();
        return Stream.of(
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.issueTime(null),
                        "PoP JWT missing mandatory iat claim"),
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.issueTime(new Date(now - 600_000)),
                        "PoP JWT expired (iat too old)"),
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.expirationTime(new Date(now - 1_000)),
                        "PoP JWT has expired"),
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.audience("https://other.example.com"),
                        "PoP JWT aud does not match this issuer"),
                Arguments.of((UnaryOperator<JWTClaimsSet.Builder>) b -> b.audience((String) null),
                        "PoP JWT aud does not match this issuer"));
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource("invalidPopClaims")
    void validateHeaders_whenPopClaimsInvalid_throws(UnaryOperator<JWTClaimsSet.Builder> popCustomizer,
                                                     String expectedMessage) throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, popCustomizer);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals(expectedMessage, ex.getMessage());
    }

    @Test
    void validateHeaders_whenPopJtiReused_throwsReplay() throws JOSEException {
        trustIssuer(List.of());
        String wia = buildWia(b -> b.subject(CLIENT_ID).claim("cnf", cnfJwk(popKey)));
        String pop = buildPop(popKey, b -> b);
        service.validateHeaders(wia, pop, ISSUER_URL);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.validateHeaders(wia, pop, ISSUER_URL));
        assertEquals("PoP jti replay detected", ex.getMessage());
    }

    // --- helpers ---

    private void trustIssuer(List<TrustedProvider> providers) {
        when(trustedWalletProvidersService.isWalletProviderTrusted(WIA_ISSUER)).thenReturn(true);
        lenient().when(trustedWalletProvidersService.getAllTrustedProviders()).thenReturn(providers);
    }

    private static Map<String, Object> cnfJwk(ECKey key) {
        return Map.of("jwk", key.toPublicJWK().toJSONObject());
    }

    private JWTClaimsSet.Builder baseWiaClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(WIA_ISSUER)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 300_000));
    }

    private String buildWia(UnaryOperator<JWTClaimsSet.Builder> claimsCustomizer) throws JOSEException {
        return buildWia(wiaSigningKey.toPublicJWK(), claimsCustomizer);
    }

    private String buildWia(ECKey headerJwk, UnaryOperator<JWTClaimsSet.Builder> claimsCustomizer)
            throws JOSEException {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-client-attestation+jwt"));
        if (headerJwk != null) {
            header.jwk(headerJwk);
        }
        return sign(header.build(), claimsCustomizer.apply(baseWiaClaims()).build());
    }

    private String sign(JWSHeader header, JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(wiaSigningKey));
        return jwt.serialize();
    }

    private JWTClaimsSet.Builder basePopClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(CLIENT_ID)
                .audience(ISSUER_URL)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 60_000));
    }

    private String buildPop(ECKey signer, UnaryOperator<JWTClaimsSet.Builder> claimsCustomizer)
            throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-client-attestation-pop+jwt"))
                .build();
        SignedJWT jwt = new SignedJWT(header, claimsCustomizer.apply(basePopClaims()).build());
        jwt.sign(new ECDSASigner(signer));
        return jwt.serialize();
    }

    private String buildPopWithHeaderJwk(ECKey signer) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-client-attestation-pop+jwt"))
                .jwk(signer.toPublicJWK())
                .build();
        SignedJWT jwt = new SignedJWT(header, basePopClaims().build());
        jwt.sign(new ECDSASigner(signer));
        return jwt.serialize();
    }

    private static String toPem(PublicKey key) {
        String b64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----";
    }

    private static X509Certificate selfSignedCert(ECKey key) throws Exception {
        X500Name name = new X500Name("CN=Wallet Provider");
        Date now = new Date();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, now, new Date(now.getTime() + 86_400_000L), name, key.toECPublicKey());
        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(key.toECPrivateKey());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
