package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CorsIntegrationIT {

    @Autowired
    private WebTestClient webTestClient;

    @Test
    void optionsRequest_FromAllowedOrigin_ReturnsCorsHeaders() {
      String allowedOrigin = "http://localhost:4200";

        webTestClient.options()
                .uri("/.well-known/openid-credential-issuer")
                .header("Origin", allowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "Api-Version, Content-Type")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", allowedOrigin)
                .expectHeader().valueEquals("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
                .expectHeader().valueMatches("Access-Control-Allow-Headers", ".*Api-Version.*");
    }

    @Test
    void optionsRequest_FromDisallowedOrigin_DoesNotReturnCorsHeaders() {
        String disallowedOrigin = "https://malicious.com";

        webTestClient.options()
                .uri("/.well-known/openid-credential-issuer")
                .header("Origin", disallowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isForbidden();
        // Spring WebFlux CORS filter returns 403 Forbidden for disallowed origins in preflight if configured strictly,
        // or just omits headers. In our case, it should at least not have the ACAO header.
    }

    @Test
    void optionsRequest_FromLocalhost4200_ReturnsCorsHeaders() {
        String allowedOrigin = "http://localhost:4200";

        webTestClient.options()
                .uri("/oid4vci/v1/authorize")
                .header("Origin", allowedOrigin)
                .header("Access-Control-Request-Method", "GET")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Access-Control-Allow-Origin", allowedOrigin);
    }
}
