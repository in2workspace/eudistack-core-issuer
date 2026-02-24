package es.in2.issuer.backend.signing.infrastructure.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.dto.SigningContext;
import es.in2.issuer.backend.signing.domain.model.dto.SigningRequest;
import es.in2.issuer.backend.signing.domain.model.SigningType;
import es.in2.issuer.backend.signing.domain.exception.SigningException;
import es.in2.issuer.backend.signing.domain.util.Base64UrlUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class InMemorySigningProviderTest {

    @InjectMocks
    private InMemorySigningProvider provider;

    @Test
    void signReturnsJwsLikeStringForJades() throws Exception {
        String payloadJson = "{\"foo\":\"bar\"}";
        SigningContext ctx = new SigningContext("token", "proc", "email");
        SigningRequest req = new SigningRequest(SigningType.JADES, payloadJson, ctx);

        ObjectMapper om = new ObjectMapper();

        StepVerifier.create(provider.sign(req))
                .assertNext(res -> {
                    assertEquals(SigningType.JADES, res.type());

                    String jws = res.data();
                    assertNotNull(jws);
                    assertFalse(jws.isBlank());

                    String[] parts = jws.split("\\.", -1);
                    assertEquals(3, parts.length, "JWS debe tener 3 partes separadas por '.'");

                    // Decode header/payload (Base64URL)
                    String headerJson;
                    String decodedPayload;
                    try {
                        headerJson = new String(Base64UrlUtils.decode(parts[0]), StandardCharsets.UTF_8);
                        decodedPayload = new String(Base64UrlUtils.decode(parts[1]), StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException e) {
                        fail("Header/Payload no son Base64URL válidos: " + e.getMessage());
                        return;
                    }

                    // Parse JSON and assert fields
                    try {
                        JsonNode headerNode = om.readTree(headerJson);
                        assertTrue(headerNode.has("alg"));
                        assertTrue(headerNode.has("typ"));

                        assertEquals("JWT", headerNode.get("typ").asText());

                        // Si realmente es alg=none, lo normal es firma vacía, pero lo dejamos “condicional”
                        String alg = headerNode.get("alg").asText();
                        if ("none".equalsIgnoreCase(alg)) {
                            assertTrue(parts[2].isEmpty(), "Con alg=none la firma debería ser vacía");
                        }

                        // Compare payload by JSON equivalence
                        JsonNode expectedPayload = om.readTree(payloadJson);
                        JsonNode actualPayload = om.readTree(decodedPayload);
                        assertEquals(expectedPayload, actualPayload, "El payload decodificado no coincide (por equivalencia JSON)");
                    } catch (Exception e) {
                        fail("Header o payload no son JSON válidos: " + e.getMessage());
                    }
                })
                .verifyComplete();
    }


    @Test
    void signReturnsBase64ForCose() {
        SigningContext context = new SigningContext("token", "proc", "email");
        String base64 = java.util.Base64.getEncoder().encodeToString("cborbytes".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        SigningRequest request = new SigningRequest(SigningType.COSE, base64, context);
        StepVerifier.create(provider.sign(request))
                .assertNext(result -> {
                    assertEquals(SigningType.COSE, result.type());
                    assertEquals(result.data(),base64);
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
        SigningRequest request = new SigningRequest(null, "data", context);
        StepVerifier.create(provider.sign(request))
                .expectError(SigningException.class)
                .verify();
    }

    @Test
    void signThrowsSigningExceptionOnNullContext() {
        SigningRequest request = new SigningRequest(SigningType.JADES, "data", null);
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
                new SigningRequest(SigningType.JADES, null, validContext), // null data
                new SigningRequest(SigningType.JADES, "   ", validContext), // blank data
                new SigningRequest(SigningType.JADES, "data", new SigningContext(null, "proc", "email")), // null token
                new SigningRequest(SigningType.JADES, "data", new SigningContext("   ", "proc", "email")) // blank token
        );
    }
}
