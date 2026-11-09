package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.issuance.domain.model.dto.IssuanceRequest;
import es.in2.issuer.backend.shared.infrastructure.config.ExchangeContextWebFilter;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import jakarta.validation.Valid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * EUD-254 contract, EUD-268: a request body rejected for the shape or format of a field is a
 * BAD_REQUEST problem whose {@code violations} name each field as the client sent it.
 */
class BadRequestViolationsTest {

    private static final String PATH = "/api/v1/stub-issuances";
    private static final String VALID_FIELDS = """
            "credential_configuration_id": "learcredential.employee.sd.1", "payload": {}""";

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToController(new StubController())
                .controllerAdvice(new SharedExceptionHandler(new ErrorResponseFactory()))
                .webFilter(new ExchangeContextWebFilter())
                .build();
    }

    @Test
    void aMissingEmailIsABadRequestNamingTheField() {
        post("{" + VALID_FIELDS + "}")
                .expectStatus().isBadRequest()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.status").isEqualTo(400)
                .jsonPath("$.violations.length()").isEqualTo(1)
                .jsonPath("$.violations[0].field").isEqualTo("email")
                .jsonPath("$.violations[0].message").isEqualTo("email is required");
    }

    @Test
    void aFieldIsNamedAsInTheContractNotAsInJava() {
        post("""
                {"credential_configuration_id": "bad id!", "payload": {}, "email": "a@b.example"}""")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.violations[0].field").isEqualTo("credential_configuration_id");
    }

    @Test
    void everyInvalidFieldIsListed() {
        post("""
                {"credential_configuration_id": "bad id!", "payload": {}, "email": "not-an-email"}""")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.violations.length()").isEqualTo(2)
                .jsonPath("$.violations[?(@.field == 'email')]").exists()
                .jsonPath("$.violations[?(@.field == 'credential_configuration_id')]").exists();
    }

    @Test
    void theDetailNeverEchoesTheRejectedValues() {
        post("""
                {"credential_configuration_id": "learcredential.employee.sd.1", "payload": {}, "email": "secret-not-an-email"}""")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.detail").isEqualTo("The request has fields that are not valid");
    }

    @Test
    void aMissingRequiredPropertyNamesTheField() {
        post("""
                {"payload": {}, "email": "a@b.example"}""")
                .expectStatus().isBadRequest()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("credential_configuration_id");
    }

    @Test
    void aFieldOfTheWrongTypeNamesTheField() {
        post("{" + VALID_FIELDS + ", \"email\": {\"x\": 1}}")
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations[0].field").isEqualTo("email");
    }

    @Test
    void aBodyThatIsNotJsonIsABadRequestWithoutViolations() {
        post("{not json")
                .expectStatus().isBadRequest()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST")
                .jsonPath("$.violations").doesNotExist();
    }

    private WebTestClient.ResponseSpec post(String body) {
        return client.post().uri(PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange();
    }

    @RestController
    static class StubController {

        @PostMapping(value = PATH, consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
        Mono<Map<String, String>> create(@Valid @RequestBody IssuanceRequest request) {
            return Mono.just(Map.of("status", "ok"));
        }
    }
}
