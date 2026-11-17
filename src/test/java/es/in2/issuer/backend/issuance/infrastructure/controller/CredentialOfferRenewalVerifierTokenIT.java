package es.in2.issuer.backend.issuance.infrastructure.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;

/**
 * EUD-295 ES-03, as narrowed by the review of round 3: an expired access token of the verifier is
 * rejected with 401 {@code problem+json}. The verifier is a stub that publishes its metadata and
 * JWKS, so the real {@code VerifierServiceImpl} checks the signature and the expiration -- nothing
 * of the authentication is mocked.
 *
 * <p>Tokens signed by the issuer itself are out of this criterion: their expiration is not checked
 * (H-04, and the issue of the review called IC-A), which is not code of this order.
 */
class CredentialOfferRenewalVerifierTokenIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String ORG = "operator-org-for-verifier-token-it";
    private static final Map<String, Object> ORG_ADMIN =
            Map.of("type", "domain", "domain", TENANT, "function", "Onboarding", "action", List.of("Execute"));

    private static final ECKey VERIFIER_KEY = generateKey();
    private static final HttpServer VERIFIER = startVerifier();

    @DynamicPropertySource
    static void verifierProperties(DynamicPropertyRegistry registry) {
        registry.add("app.verifier-internal-url", () -> "http://localhost:" + VERIFIER.getAddress().getPort());
    }

    @AfterAll
    static void stopVerifier() {
        VERIFIER.stop(0);
    }

    /** Control: a verifier token in force passes authentication and the renewal is decided (404, no such id). */
    @Test
    void renew_verifierTokenInForce_isAuthenticated() {
        renew(verifierToken(Instant.now().plus(Duration.ofHours(1))))
                .expectStatus().isNotFound();
    }

    /** ES-03. */
    @Test
    void renew_expiredVerifierToken_is401ProblemJson() {
        renew(verifierToken(Instant.now().minus(Duration.ofMinutes(1))))
                .expectStatus().isUnauthorized()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);
    }

    private WebTestClient.ResponseSpec renew(String token) {
        return webTestClient().post().uri("/api/v1/issuances/{id}/credential-offer", UUID.randomUUID())
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .header("X-Forwarded-For", "10.29.5.3")
                .exchange();
    }

    /** An access token as the verifier issues it: {@code iss} is the verifier's public URL. */
    private String verifierToken(Instant expiresAt) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("http://localhost:" + port + "/verifier")
                .issueTime(Date.from(expiresAt.minus(Duration.ofHours(2))))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .claim("mandator", Map.of("organizationIdentifier", ORG))
                .claim("power", List.of(ORG_ADMIN))
                .claim("tenant", TENANT)
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(VERIFIER_KEY.getKeyID()).build(),
                claims);
        try {
            jwt.sign(new ECDSASigner(VERIFIER_KEY));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt.serialize();
    }

    private static ECKey generateKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("verifier-it-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The verifier's metadata and JWKS, the two documents the issuer fetches to check a token. */
    private static HttpServer startVerifier() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            String origin = "http://localhost:" + server.getAddress().getPort();
            respond(server, "/.well-known/openid-configuration",
                    "{\"issuer\":\"" + origin + "/verifier\",\"jwks_uri\":\"" + origin + "/verifier/oauth2/jwks\"}");
            respond(server, "/verifier/oauth2/jwks", new JWKSet(VERIFIER_KEY.toPublicJWK()).toString());
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void respond(HttpServer server, String path, String json) {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        server.createContext(path, exchange -> {
            exchange.getResponseHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
    }
}
