package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.ProofValidationException;
import es.in2.issuer.backend.shared.domain.service.JWTService;
import es.in2.issuer.backend.shared.domain.spi.TransientStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Stream;

import static es.in2.issuer.backend.shared.domain.util.Constants.SUPPORTED_PROOF_ALG;
import static es.in2.issuer.backend.shared.domain.util.Constants.SUPPORTED_PROOF_TYP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Asserts the exact rejection reason of {@link ProofValidationServiceImpl} so every header/payload branch is
 * reached (the original suite only checks the exception type, so several cases fail earlier than intended).
 */
@ExtendWith(MockitoExtension.class)
class ProofValidationServiceImplBranchesTest {

    private static final String AUD = "https://issuer.example.com";
    private static final String NONCE = "nonce-1";
    private static final Set<String> ALLOWED = Set.of(SUPPORTED_PROOF_ALG);

    @Mock
    private JWTService jwtService;
    @Mock
    private TransientStore<String> nonceCacheStore;

    private ProofValidationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new ProofValidationServiceImpl(jwtService, nonceCacheStore);
    }

    // --- header ---

    static Stream<Arguments> invalidHeaders() throws JOSEException {
        String publicJwk = JSONObjectUtils.toJSONString(
                new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONObject());
        String typ = "\"typ\":\"" + SUPPORTED_PROOF_TYP + "\"";
        String alg = "\"alg\":\"" + SUPPORTED_PROOF_ALG + "\"";
        return Stream.of(
                Arguments.of(Named.of("HMAC alg", "{\"alg\":\"HS256\"," + typ + ",\"kid\":\"k\"}"), ALLOWED,
                        "invalid_proof: alg not allowed"),
                Arguments.of(Named.of("null allowed algs", "{" + alg + "," + typ + ",\"kid\":\"k\"}"), null,
                        "invalid_proof: alg not allowed by configuration"),
                Arguments.of(Named.of("empty allowed algs", "{" + alg + "," + typ + ",\"kid\":\"k\"}"), Set.of(),
                        "invalid_proof: alg not allowed by configuration"),
                Arguments.of(Named.of("alg not in allowed algs", "{" + alg + "," + typ + ",\"kid\":\"k\"}"),
                        Set.of("RS256"), "invalid_proof: alg not allowed by configuration"),
                Arguments.of(Named.of("no key material", "{" + alg + "," + typ + "}"), ALLOWED,
                        "invalid_proof: exactly one of kid, jwk or x5c must be present"),
                Arguments.of(Named.of("kid and jwk", "{" + alg + "," + typ + ",\"kid\":\"k\",\"jwk\":" + publicJwk + "}"),
                        ALLOWED, "invalid_proof: exactly one of kid, jwk or x5c must be present"),
                Arguments.of(Named.of("x5c only", "{" + alg + "," + typ + ",\"x5c\":[\"MIIB\"]}"), ALLOWED,
                        "invalid_proof: x5c not supported"));
    }

    @ParameterizedTest
    @MethodSource("invalidHeaders")
    void verifyProof_withInvalidHeader_rejectsWithReason(String headerJson, Set<String> allowedAlgs,
                                                        String expectedMessage) {
        // Arrange
        String jwt = rawJwt(headerJson, validPayload());

        // Act + Assert
        StepVerifier.create(service.verifyProof(jwt, allowedAlgs, AUD))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ProofValidationException.class)
                        .hasMessage(expectedMessage))
                .verify();
    }

    @Test
    void verifyProof_withKidAndEmptyX5c_treatsX5cAsAbsentAndValidates() {
        // Arrange
        String header = "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP
                + "\",\"kid\":\"did:key:z1\",\"x5c\":[]}";
        String jwt = rawJwt(header, validPayload());
        when(nonceCacheStore.get(NONCE)).thenReturn(Mono.just(NONCE));
        when(jwtService.validateJwtSignatureReactive(any(SignedJWT.class))).thenReturn(Mono.just(true));
        when(nonceCacheStore.delete(NONCE)).thenReturn(Mono.empty());

        // Act + Assert
        StepVerifier.create(service.verifyProof(jwt, ALLOWED, AUD))
                .expectNext(true)
                .verifyComplete();
    }

    // --- payload ---

    static Stream<Arguments> invalidPayloads() {
        long now = Instant.now().getEpochSecond();
        return Stream.of(
                Arguments.of(Named.of("blank aud", "{\"aud\":\" \",\"iat\":" + now + "}"),
                        "Invalid JWT payload: aud is missing"),
                Arguments.of(Named.of("aud list without issuer", "{\"aud\":[\"x\",\"y\"],\"iat\":" + now + "}"),
                        "Invalid JWT payload: aud must be '" + AUD + "' but was [x, y]"),
                Arguments.of(Named.of("numeric aud", "{\"aud\":5,\"iat\":" + now + "}"),
                        "Invalid JWT payload: aud must be '" + AUD + "' but was 5"),
                Arguments.of(Named.of("blank nonce", "{\"aud\":\"" + AUD + "\",\"iat\":" + now + ",\"nonce\":\" \"}"),
                        "invalid_proof: nonce is missing"));
    }

    @ParameterizedTest
    @MethodSource("invalidPayloads")
    void verifyProof_withInvalidPayload_rejectsWithReason(String payloadJson, String expectedMessage) {
        // Arrange
        String header = "{\"alg\":\"" + SUPPORTED_PROOF_ALG + "\",\"typ\":\"" + SUPPORTED_PROOF_TYP
                + "\",\"kid\":\"did:key:z1\"}";
        String jwt = rawJwt(header, payloadJson);

        // Act + Assert
        StepVerifier.create(service.verifyProof(jwt, ALLOWED, AUD))
                .expectErrorSatisfies(e -> assertThat(e)
                        .isInstanceOf(ProofValidationException.class)
                        .hasMessage(expectedMessage))
                .verify();
    }

    // --- helpers ---

    private static String validPayload() {
        return "{\"aud\":\"" + AUD + "\",\"iat\":" + Instant.now().getEpochSecond() + ",\"nonce\":\"" + NONCE + "\"}";
    }

    private static String rawJwt(String headerJson, String payloadJson) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString("signature".getBytes(StandardCharsets.UTF_8));
    }
}
