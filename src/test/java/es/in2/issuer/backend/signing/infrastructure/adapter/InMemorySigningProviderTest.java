package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class InMemorySigningProviderTest {

    private static final String TEST_CERT_PATH = resolveTestResource("test-cert.pem");
    private static final String TEST_KEY_PATH = resolveTestResource("test-key-pkcs8.pem");

    private final InMemorySigningProvider provider = new InMemorySigningProvider(TEST_CERT_PATH, TEST_KEY_PATH);

    private static String resolveTestResource(String name) {
        return Path.of("src", "test", "resources", name).toAbsolutePath().toString();
    }

    @Test
    void constructorThrowsWhenCertMissing() {
        assertThrows(IllegalStateException.class,
                () -> new InMemorySigningProvider("/nonexistent/cert.pem", TEST_KEY_PATH));
    }

    @Test
    void constructorThrowsWhenKeyMissing() {
        assertThrows(IllegalStateException.class,
                () -> new InMemorySigningProvider(TEST_CERT_PATH, "/nonexistent/key.pem"));
    }

    @Test
    void signReturnsJwsWithX5cForJades() {
        String payloadJson = "{\"foo\":\"bar\"}";
        SigningContext ctx = new SigningContext("token", "proc", "email");
        SigningRequest req = new SigningRequest(SigningType.JADES, payloadJson, ctx, "JWT");

        ObjectMapper om = new ObjectMapper();

        StepVerifier.create(provider.sign(req))
                .assertNext(res -> {
                    assertEquals(SigningType.JADES, res.type());

                    String jws = res.data();
                    assertNotNull(jws);
                    assertFalse(jws.isBlank());

                    String[] parts = jws.split("\\.", -1);
                    assertEquals(3, parts.length, "JWS must have 3 parts");

                    String headerJson;
                    String decodedPayload;
                    try {
                        headerJson = new String(Base64UrlUtils.decode(parts[0]), StandardCharsets.UTF_8);
                        decodedPayload = new String(Base64UrlUtils.decode(parts[1]), StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException e) {
                        fail("Header/Payload not valid Base64URL: " + e.getMessage());
                        return;
                    }

                    try {
                        JsonNode headerNode = om.readTree(headerJson);
                        assertTrue(headerNode.has("alg"), "Header must have alg");
                        assertTrue(headerNode.has("typ"), "Header must have typ");
                        assertTrue(headerNode.has("x5c"), "Header must have x5c");

                        assertEquals("ES256", headerNode.get("alg").asText(), "Algorithm must be ES256 for EC key");
                        assertTrue(headerNode.get("x5c").isArray(), "x5c must be an array");
                        assertTrue(headerNode.get("x5c").size() > 0, "x5c must not be empty");

                        // Verify signature part is not empty (real signature)
                        assertFalse(parts[2].isEmpty(), "Signature must not be empty");

                        // Compare payload by JSON equivalence
                        JsonNode expectedPayload = om.readTree(payloadJson);
                        JsonNode actualPayload = om.readTree(decodedPayload);
                        assertEquals(expectedPayload, actualPayload, "Decoded payload must match original");
                    } catch (Exception e) {
                        fail("Header or payload not valid JSON: " + e.getMessage());
                    }
                })
                .verifyComplete();
    }

    @Test
    void signReturnsBase64ForCose() {
        SigningContext context = new SigningContext("token", "proc", "email");
        String base64 = java.util.Base64.getEncoder().encodeToString("cborbytes".getBytes(StandardCharsets.UTF_8));
        SigningRequest request = new SigningRequest(SigningType.COSE, base64, context, null);
        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assertEquals(SigningType.COSE, result.type());
                    assertEquals(result.data(), base64);
                })
                .verifyComplete();
    }

    @Test
    void signThrowsSigningExceptionOnNullRequest() {
        StepVerifier.create(provider.sign(null))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullType() {
        SigningContext context = new SigningContext("token", "proc", "email");
        SigningRequest request = new SigningRequest(null, "data", context, "JWT");
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullContext() {
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", null, "JWT");
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @ParameterizedTest
    @MethodSource("invalidSigningRequests")
    void signThrowsSigningExceptionOnInvalidRequest(SigningRequest request) {
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    private static Stream<SigningRequest> invalidSigningRequests() {
        SigningContext validContext = new SigningContext("token", "proc", "email");
        return Stream.of(
                new SigningRequest(SigningType.JADES, null, validContext, "JWT"),
                new SigningRequest(SigningType.JADES, "   ", validContext, "JWT"),
                new SigningRequest(SigningType.JADES, "data", new SigningContext(null, "proc", "email"), "JWT"),
                new SigningRequest(SigningType.JADES, "data", new SigningContext("   ", "proc", "email"), "JWT")
        );
    }
}
