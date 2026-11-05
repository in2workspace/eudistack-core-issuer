package es.in2.issuer.backend.shared.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.exception.IssuanceNotFoundException;
import es.in2.issuer.backend.shared.domain.exception.MalformedIssuanceIdException;
import es.in2.issuer.backend.shared.infrastructure.config.ExchangeContextWebFilter;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * EUD-307: every error SharedExceptionHandler writes on the management API is served as
 * application/problem+json (RFC 9457), even from an endpoint that declares {@code produces = application/json}
 * and for a client that accepts only application/json -- what the public API guides promise. The
 * protocol endpoints keep application/json.
 */
class ProblemDetailsContentTypeTest {

    private WebTestClient client;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToController(new StubController())
                .controllerAdvice(new SharedExceptionHandler(new ErrorResponseFactory()))
                .webFilter(new ExchangeContextWebFilter())
                .build();
    }

    @Test
    void SharedExceptionHandler_handleIssuanceNotFoundException_servesProblemJson() {
        client.get().uri("/api/v1/stub/{id}", "00000000-0000-0000-0000-000000000000")
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("issuance_not_found")
                .jsonPath("$.status").isEqualTo(404)
                .jsonPath("$.instance").exists();
    }

    @Test
    void SharedExceptionHandler_handleMalformedIssuanceIdException_servesProblemJsonWithBadRequestType() {
        client.get().uri("/api/v1/stub/{id}", "not-a-uuid")
                .exchange()
                .expectStatus().isBadRequest()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
                .expectBody()
                .jsonPath("$.type").isEqualTo("BAD_REQUEST");
    }

    @Test
    void SharedExceptionHandler_protocolEndpointError_keepsApplicationJson() {
        client.get().uri("/oid4vci/v1/stub")
                .exchange()
                .expectStatus().isNotFound()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON);
    }

    @Test
    void StubController_success_keepsApplicationJson() {
        client.get().uri("/api/v1/stub/ok")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_JSON);
    }

    @RestController
    static class StubController {

        @GetMapping(value = "/api/v1/stub/ok", produces = MediaType.APPLICATION_JSON_VALUE)
        Mono<Map<String, String>> ok() {
            return Mono.just(Map.of("status", "ok"));
        }

        @GetMapping(value = "/api/v1/stub/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
        Mono<Map<String, String>> detail(@PathVariable("id") String id) {
            return "not-a-uuid".equals(id)
                    ? Mono.error(new MalformedIssuanceIdException())
                    : Mono.error(new IssuanceNotFoundException("No issuance found for the given id"));
        }

        @GetMapping(value = "/oid4vci/v1/stub", produces = MediaType.APPLICATION_JSON_VALUE)
        Mono<Map<String, String>> protocol() {
            return Mono.error(new IssuanceNotFoundException("No issuance found for the given id"));
        }
    }
}
