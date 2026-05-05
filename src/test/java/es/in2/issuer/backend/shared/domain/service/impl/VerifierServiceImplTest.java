package es.in2.issuer.backend.shared.domain.service.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.issuer.backend.shared.domain.exception.JWTParsingException;
import es.in2.issuer.backend.shared.domain.exception.JWTVerificationException;
import es.in2.issuer.backend.shared.domain.exception.WellKnownInfoFetchException;
import es.in2.issuer.backend.shared.domain.model.dto.OpenIDProviderMetadata;
import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static es.in2.issuer.backend.shared.domain.util.Constants.CONTENT_TYPE;
import static es.in2.issuer.backend.shared.domain.util.Constants.CONTENT_TYPE_APPLICATION_JSON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class VerifierServiceImplTest {

    private static final String INTERNAL_VERIFIER_BASE =
            "http://verifier-core.stg.eudistack.local:8080/verifier";
    private static final String WELL_KNOWN_ENDPOINT =
            INTERNAL_VERIFIER_BASE + "/.well-known/openid-configuration";
    private static final String PUBLIC_JWKS_URI =
            "https://verifier.example.com/verifier/jwks";
    private static final String INTERNAL_JWKS_URI =
            "http://verifier-core.stg.eudistack.local:8080/verifier/jwks";

    @Mock
    private UrlResolver urlResolver;

    @BeforeEach
    void setUp() {
        when(urlResolver.internalVerifierBaseUrl()).thenReturn(INTERNAL_VERIFIER_BASE);
    }

    @Test
    void getWellKnownInfo_composesUrlFromInternalBasePath_preservingContextPath() {
        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        ClientResponse clientResponse = jsonResponse(HttpStatus.OK, metadataJson(PUBLIC_JWKS_URI));
        when(exchangeFunction.exchange(any())).thenReturn(Mono.just(clientResponse));

        WebClient webClient = WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();

        VerifierServiceImpl verifierService = new VerifierServiceImpl(webClient, urlResolver);

        OpenIDProviderMetadata expected = OpenIDProviderMetadata.builder()
                .issuer("https://verifier.example.com")
                .authorizationEndpoint("https://verifier.example.com/authorize")
                .tokenEndpoint("https://verifier.example.com/token")
                .jwksUri(PUBLIC_JWKS_URI)
                .build();

        StepVerifier.create(verifierService.getWellKnownInfo())
                .expectNext(expected)
                .verifyComplete();

        verify(urlResolver).internalVerifierBaseUrl();
        verifyNoMoreInteractions(urlResolver);

        ArgumentCaptor<ClientRequest> requestCaptor = ArgumentCaptor.forClass(ClientRequest.class);
        verify(exchangeFunction).exchange(requestCaptor.capture());

        ClientRequest request = requestCaptor.getValue();
        assertEquals(WELL_KNOWN_ENDPOINT, request.url().toString());
        assertEquals(HttpMethod.GET, request.method());
    }

    @Test
    void getWellKnownInfo_whenWebClientFails_returnsWellKnownInfoFetchException() {
        ExchangeFunction exchangeFunction = request -> Mono.error(new RuntimeException("boom"));

        VerifierServiceImpl verifierService = new VerifierServiceImpl(
                webClient(exchangeFunction),
                urlResolver
        );

        StepVerifier.create(verifierService.getWellKnownInfo())
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(WellKnownInfoFetchException.class);
                    assertThat(error).hasMessage("Error fetching OpenID Provider Metadata");
                })
                .verify();
    }

    @Test
    void verifyToken_whenRsaTokenIsValid_completesSuccessfully() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", futureExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks(rsaKey.toPublicJWK());

        StepVerifier.create(verifierService.verifyToken(token))
                .verifyComplete();
    }

    @Test
    void verifyToken_whenEcTokenIsValid_completesSuccessfully() throws Exception {
        ECKey ecKey = ecKey("ec-key");
        String token = signedEcToken(ecKey, "ec-key", futureExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks(ecKey.toPublicJWK());

        StepVerifier.create(verifierService.verifyToken(token))
                .verifyComplete();
    }

    @Test
    void verifyTokenWithoutExpiration_whenTokenIsExpired_completesSuccessfully() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", pastExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks(rsaKey.toPublicJWK());

        StepVerifier.create(verifierService.verifyTokenWithoutExpiration(token))
                .verifyComplete();
    }

    @Test
    void verifyToken_whenTokenCannotBeParsed_returnsJwtParsingException() {
        VerifierServiceImpl verifierService = verifierServiceWithJwks(new JWKSet().toJSONObject().toString());

        StepVerifier.create(verifierService.verifyToken("not-a-jwt"))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTParsingException.class);
                    assertThat(error).hasMessage("Error parsing JWT");
                })
                .verify();
    }

    @Test
    void verifyToken_whenExpirationIsMissing_returnsJwtVerificationException() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", null);

        VerifierServiceImpl verifierService = verifierServiceWithJwks(rsaKey.toPublicJWK());

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Token has expired");
                })
                .verify();
    }

    @Test
    void verifyToken_whenTokenIsExpired_returnsJwtVerificationException() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", pastExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks(rsaKey.toPublicJWK());

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Token has expired");
                })
                .verify();
    }

    @Test
    void verifyToken_whenSignatureIsInvalid_returnsJwtVerificationException() throws Exception {
        RSAKey signingKey = rsaKey("rsa-key");
        RSAKey differentPublicKeyWithSameKid = rsaKey("rsa-key");

        String token = signedRsaToken(signingKey, "rsa-key", futureExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks(differentPublicKeyWithSameKid.toPublicJWK());

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Invalid token signature");
                })
                .verify();
    }

    @Test
    void verifyToken_whenNoMatchingJwkExists_returnsJwtVerificationException() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", futureExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks(new JWKSet().toString());

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Error verifying JWT signature");
                })
                .verify();
    }

    @Test
    void verifyToken_whenJwkTypeIsOct_returnsJwtVerificationException() throws Exception {
        RSAKey signingKey = rsaKey("oct-key");
        String token = signedRsaToken(signingKey, "oct-key", futureExpiration());

        OctetSequenceKey octKey = new OctetSequenceKey.Builder("0123456789abcdef".getBytes())
                .keyID("oct-key")
                .build();

        VerifierServiceImpl verifierService = verifierServiceWithJwks(octKey);

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Error verifying JWT signature");
                })
                .verify();
    }

    @Test
    void verifyToken_whenJwkTypeIsUnsupported_returnsJwtVerificationException() throws Exception {
        RSAKey signingKey = rsaKey("okp-key");
        String token = signedRsaToken(signingKey, "okp-key", futureExpiration());

        String jwksWithUnsupportedOkpKey = """
            {
              "keys": [
                {
                  "kty": "OKP",
                  "kid": "okp-key",
                  "crv": "Ed25519",
                  "x": "11qYAYdkxQ5GIy7YH-p1RRL3y9fVqEJSMawz-X9aNfA"
                }
              ]
            }
            """;

        VerifierServiceImpl verifierService = verifierServiceWithJwks(jwksWithUnsupportedOkpKey);

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Error verifying JWT signature");
                })
                .verify();
    }

    @Test
    void verifyToken_whenJwksCannotBeParsed_returnsJwtVerificationException() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", futureExpiration());

        VerifierServiceImpl verifierService = verifierServiceWithJwks("invalid-jwks");

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Error parsing the JWK Set");
                })
                .verify();
    }

    @Test
    void verifyToken_whenJwksFetchFails_returnsJwtVerificationException() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", futureExpiration());

        ExchangeFunction exchangeFunction = request -> {
            if (request.url().toString().equals(WELL_KNOWN_ENDPOINT)) {
                return Mono.just(jsonResponse(HttpStatus.OK, metadataJson(PUBLIC_JWKS_URI)));
            }
            return Mono.error(new RuntimeException("jwks unavailable"));
        };

        when(urlResolver.rewriteToInternalVerifier(PUBLIC_JWKS_URI)).thenReturn(INTERNAL_JWKS_URI);

        VerifierServiceImpl verifierService = new VerifierServiceImpl(
                webClient(exchangeFunction),
                urlResolver
        );

        StepVerifier.create(verifierService.verifyToken(token))
                .expectErrorSatisfies(error -> {
                    assertThat(error).isInstanceOf(JWTVerificationException.class);
                    assertThat(error).hasMessage("Error fetching the JWK Set");
                })
                .verify();
    }

    @Test
    void verifyToken_whenCalledTwice_fetchesJwksOnlyOnceBecauseItIsCached() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String firstToken = signedRsaToken(rsaKey, "rsa-key", futureExpiration());
        String secondToken = signedRsaToken(rsaKey, "rsa-key", futureExpiration());

        AtomicInteger wellKnownRequests = new AtomicInteger();
        AtomicInteger jwksRequests = new AtomicInteger();

        ExchangeFunction exchangeFunction = request -> {
            String url = request.url().toString();

            if (url.equals(WELL_KNOWN_ENDPOINT)) {
                wellKnownRequests.incrementAndGet();
                return Mono.just(jsonResponse(HttpStatus.OK, metadataJson(PUBLIC_JWKS_URI)));
            }

            if (url.equals(INTERNAL_JWKS_URI)) {
                jwksRequests.incrementAndGet();
                return Mono.just(jsonResponse(HttpStatus.OK, jwksJson(rsaKey.toPublicJWK())));
            }

            return Mono.error(new IllegalArgumentException("Unexpected URL: " + url));
        };

        when(urlResolver.rewriteToInternalVerifier(PUBLIC_JWKS_URI)).thenReturn(INTERNAL_JWKS_URI);

        VerifierServiceImpl verifierService = new VerifierServiceImpl(
                webClient(exchangeFunction),
                urlResolver
        );

        StepVerifier.create(verifierService.verifyToken(firstToken))
                .verifyComplete();

        StepVerifier.create(verifierService.verifyToken(secondToken))
                .verifyComplete();

        assertThat(wellKnownRequests).hasValue(2);
        assertThat(jwksRequests).hasValue(1);
    }

    @Test
    void verifyToken_rewritesPublicJwksUriToInternalVerifierUri() throws Exception {
        RSAKey rsaKey = rsaKey("rsa-key");
        String token = signedRsaToken(rsaKey, "rsa-key", futureExpiration());

        ExchangeFunction exchangeFunction = mock(ExchangeFunction.class);
        when(exchangeFunction.exchange(any()))
                .thenReturn(Mono.just(jsonResponse(HttpStatus.OK, metadataJson(PUBLIC_JWKS_URI))))
                .thenReturn(Mono.just(jsonResponse(HttpStatus.OK, jwksJson(rsaKey.toPublicJWK()))));

        when(urlResolver.rewriteToInternalVerifier(PUBLIC_JWKS_URI)).thenReturn(INTERNAL_JWKS_URI);

        VerifierServiceImpl verifierService = new VerifierServiceImpl(
                webClient(exchangeFunction),
                urlResolver
        );

        StepVerifier.create(verifierService.verifyToken(token))
                .verifyComplete();

        ArgumentCaptor<ClientRequest> requestCaptor = ArgumentCaptor.forClass(ClientRequest.class);
        verify(exchangeFunction, org.mockito.Mockito.times(2)).exchange(requestCaptor.capture());

        List<ClientRequest> requests = requestCaptor.getAllValues();

        assertThat(requests)
                .extracting(request -> request.url().toString())
                .containsExactly(WELL_KNOWN_ENDPOINT, INTERNAL_JWKS_URI);

        assertThat(requests)
                .extracting(ClientRequest::method)
                .containsExactly(HttpMethod.GET, HttpMethod.GET);

        verify(urlResolver).internalVerifierBaseUrl();
        verify(urlResolver).rewriteToInternalVerifier(PUBLIC_JWKS_URI);
        verifyNoMoreInteractions(urlResolver);
    }

    private VerifierServiceImpl verifierServiceWithJwks(com.nimbusds.jose.jwk.JWK jwk) {
        return verifierServiceWithJwks(jwksJson(jwk));
    }

    private VerifierServiceImpl verifierServiceWithJwks(String jwksBody) {
        ExchangeFunction exchangeFunction = request -> {
            String url = request.url().toString();

            if (url.equals(WELL_KNOWN_ENDPOINT)) {
                return Mono.just(jsonResponse(HttpStatus.OK, metadataJson(PUBLIC_JWKS_URI)));
            }

            if (url.equals(INTERNAL_JWKS_URI)) {
                return Mono.just(jsonResponse(HttpStatus.OK, jwksBody));
            }

            return Mono.error(new IllegalArgumentException("Unexpected URL: " + url));
        };

        when(urlResolver.rewriteToInternalVerifier(PUBLIC_JWKS_URI)).thenReturn(INTERNAL_JWKS_URI);

        return new VerifierServiceImpl(webClient(exchangeFunction), urlResolver);
    }

    private static WebClient webClient(ExchangeFunction exchangeFunction) {
        return WebClient.builder()
                .exchangeFunction(exchangeFunction)
                .build();
    }

    private static ClientResponse jsonResponse(HttpStatus status, String body) {
        return ClientResponse.create(status)
                .header(CONTENT_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .body(body)
                .build();
    }

    private static String metadataJson(String jwksUri) {
        return """
                {
                  "issuer": "https://verifier.example.com",
                  "authorization_endpoint": "https://verifier.example.com/authorize",
                  "token_endpoint": "https://verifier.example.com/token",
                  "jwks_uri": "%s"
                }
                """.formatted(jwksUri);
    }

    private static String jwksJson(com.nimbusds.jose.jwk.JWK jwk) {
        return new JWKSet(jwk).toString();
    }

    private static RSAKey rsaKey(String keyId) throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(keyId)
                .generate();
    }

    private static ECKey ecKey(String keyId) throws JOSEException {
        return new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(keyId)
                .generate();
    }

    private static String signedRsaToken(RSAKey rsaKey, String keyId, Date expirationTime) throws Exception {
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(keyId)
                        .build(),
                claims(expirationTime)
        );

        signedJWT.sign(new RSASSASigner(rsaKey));
        return signedJWT.serialize();
    }

    private static String signedEcToken(ECKey ecKey, String keyId, Date expirationTime) throws Exception {
        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .keyID(keyId)
                        .build(),
                claims(expirationTime)
        );

        signedJWT.sign(new ECDSASigner(ecKey));
        return signedJWT.serialize();
    }

    private static JWTClaimsSet claims(Date expirationTime) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("https://verifier.example.com");

        if (expirationTime != null) {
            builder.expirationTime(expirationTime);
        }

        return builder.build();
    }

    private static Date futureExpiration() {
        return Date.from(Instant.now().plusSeconds(3600));
    }

    private static Date pastExpiration() {
        return Date.from(Instant.now().minusSeconds(3600));
    }
}