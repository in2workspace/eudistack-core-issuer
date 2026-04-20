package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;

class IssuerBaseUrlWebFilterTest {

    @Test
    void filter_usesConfiguredContextPath_overridesRequestContextPath() {
        IssuerBaseUrlWebFilter filter = new IssuerBaseUrlWebFilter("/issuer");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://kpmg.eudistack.net/credentials"));
        AtomicReference<String> captured = new AtomicReference<>();

        StepVerifier.create(filter.filter(exchange, toChain(captured))).verifyComplete();

        assertEquals("https://kpmg.eudistack.net/issuer", captured.get());
    }

    @Test
    void filter_emptyConfiguredProperty_fallsBackToRequestContextPath() {
        IssuerBaseUrlWebFilter filter = new IssuerBaseUrlWebFilter("");
        // Request path contextPath is empty for MockServerHttpRequest by default — result has no suffix
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://altia.eudistack.net/credentials"));
        AtomicReference<String> captured = new AtomicReference<>();

        StepVerifier.create(filter.filter(exchange, toChain(captured))).verifyComplete();

        assertEquals("https://altia.eudistack.net", captured.get());
    }

    @Test
    void filter_nullConfiguredProperty_fallsBackToRequestContextPath() {
        IssuerBaseUrlWebFilter filter = new IssuerBaseUrlWebFilter(null);
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://altia.eudistack.net/credentials"));
        AtomicReference<String> captured = new AtomicReference<>();

        StepVerifier.create(filter.filter(exchange, toChain(captured))).verifyComplete();

        assertEquals("https://altia.eudistack.net", captured.get());
    }

    @Test
    void filter_preservesNonDefaultPort() {
        IssuerBaseUrlWebFilter filter = new IssuerBaseUrlWebFilter("/issuer");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("http://localhost:8080/anything"));
        AtomicReference<String> captured = new AtomicReference<>();

        StepVerifier.create(filter.filter(exchange, toChain(captured))).verifyComplete();

        assertEquals("http://localhost:8080/issuer", captured.get());
    }

    @Test
    void filter_normalizesContextPathMissingLeadingSlash() {
        IssuerBaseUrlWebFilter filter = new IssuerBaseUrlWebFilter("issuer");
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://altia.eudistack.net/credentials"));
        AtomicReference<String> captured = new AtomicReference<>();

        StepVerifier.create(filter.filter(exchange, toChain(captured))).verifyComplete();

        assertEquals("https://altia.eudistack.net/issuer", captured.get());
    }

    private static WebFilterChain toChain(AtomicReference<String> captured) {
        return ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(ISSUER_BASE_URL_CONTEXT_KEY, null));
            return Mono.empty();
        });
    }
}
