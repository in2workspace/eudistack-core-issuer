package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;

class InMemorySigningProviderTest {

    private final ObjectMapper om = new ObjectMapper();

    @Test
    void signReturnsEs256JwsForJades_ephemeral() {
        InMemorySigningProvider provider = new InMemorySigningProvider();

        String payloadJson = "{\"foo\":\"bar\"}";
        SigningContext ctx = new SigningContext("token", "proc", "email");
        SigningRequest req = new SigningRequest(SigningType.JADES, payloadJson, ctx);

        StepVerifier.create(provider.sign(req))
                .assertNext(res -> {
                    assertEquals(SigningType.JADES, res.type());

                    String jws = res.data();
                    assertNotNull(jws);
                    assertFalse(jws.isBlank());

                    String[] parts = jws.split("\\.", -1);
                    assertEquals(3, parts.length, "JWS debe tener 3 partes separadas por '.'");
                    assertFalse(parts[2].isBlank(), "Con ES256 la firma no puede ser vacía");

                    String headerJson = new String(Base64UrlUtils.decode(parts[0]), StandardCharsets.UTF_8);
                    String decodedPayload = new String(Base64UrlUtils.decode(parts[1]), StandardCharsets.UTF_8);

                    JsonNode headerNode = assertDoesNotThrow(() -> om.readTree(headerJson));
                    assertEquals("ES256", headerNode.get("alg").asText());
                    assertEquals("JWT", headerNode.get("typ").asText());

                    assertFalse(headerNode.has("x5c"));

                    JsonNode expectedPayload = assertDoesNotThrow(() -> om.readTree(payloadJson));
                    JsonNode actualPayload = assertDoesNotThrow(() -> om.readTree(decodedPayload));
                    assertEquals(expectedPayload, actualPayload);
                })
                .verifyComplete();
    }

    @Test
    void signReturnsEs256JwsForJades_withX5c() throws Exception {
        var cert = org.mockito.Mockito.mock(X509Certificate.class);
        org.mockito.Mockito.when(cert.getEncoded()).thenReturn("dummy-der".getBytes(StandardCharsets.UTF_8));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        var km = new InMemoryKeyMaterialLoader.KeyMaterial(
                (java.security.interfaces.ECPrivateKey) kp.getPrivate(),
                List.of(cert)
        );

        InMemorySigningProvider provider = new InMemorySigningProvider(km);

        String payloadJson = "{\"foo\":\"bar\"}";
        SigningContext ctx = new SigningContext("token", "proc", "email");
        SigningRequest req = new SigningRequest(SigningType.JADES, payloadJson, ctx);

        StepVerifier.create(provider.sign(req))
                .assertNext(res -> {
                    assertEquals(SigningType.JADES, res.type());

                    String[] parts = res.data().split("\\.", -1);
                    assertEquals(3, parts.length);
                    assertFalse(parts[2].isBlank());

                    String headerJson = new String(Base64UrlUtils.decode(parts[0]), StandardCharsets.UTF_8);
                    JsonNode headerNode = assertDoesNotThrow(() -> om.readTree(headerJson));

                    assertEquals("ES256", headerNode.get("alg").asText());
                    assertEquals("JWT", headerNode.get("typ").asText());

                    assertTrue(headerNode.has("x5c"), "Con KeyMaterial provided debe incluir x5c");
                    assertTrue(headerNode.get("x5c").isArray());
                    assertTrue(headerNode.get("x5c").size() >= 1);

                    String x5c0 = headerNode.get("x5c").get(0).asText();
                    assertDoesNotThrow(() -> Base64.getDecoder().decode(x5c0));
                })
                .verifyComplete();
    }

    @Test
    void signReturnsBase64ForCose() {
        InMemorySigningProvider provider = new InMemorySigningProvider();

        SigningContext context = new SigningContext("token", "proc", "email");
        String base64 = Base64.getEncoder().encodeToString("cborbytes".getBytes(StandardCharsets.UTF_8));
        SigningRequest request = new SigningRequest(SigningType.COSE, base64, context);

        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assertEquals(SigningType.COSE, result.type());
                    assertEquals(base64, result.data());
                })
                .verifyComplete();
    }

    @Test
    void signThrowsSigningExceptionOnNullRequest() {
        InMemorySigningProvider provider = new InMemorySigningProvider();

        StepVerifier.create(provider.sign(null))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullType() {
        InMemorySigningProvider provider = new InMemorySigningProvider();

        SigningContext context = new SigningContext("token", "proc", "email");
        SigningRequest request = new SigningRequest(null, "data", context);

        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullContext() {
        InMemorySigningProvider provider = new InMemorySigningProvider();

        SigningRequest request = new SigningRequest(SigningType.JADES, "data", null);

        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @ParameterizedTest
    @MethodSource("invalidSigningRequests")
    void signThrowsSigningExceptionOnInvalidRequest(SigningRequest request) {
        InMemorySigningProvider provider = new InMemorySigningProvider();

        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    private static Stream<SigningRequest> invalidSigningRequests() {
        SigningContext validContext = new SigningContext("token", "proc", "email");
        return Stream.of(
                new SigningRequest(SigningType.JADES, null, validContext), // null data
                new SigningRequest(SigningType.JADES, "   ", validContext), // blank data
                new SigningRequest(SigningType.JADES, "data", new SigningContext(null, "proc", "email")), // null token
                new SigningRequest(SigningType.JADES, "data", new SigningContext("   ", "proc", "email")) // blank token
        );
    }
}