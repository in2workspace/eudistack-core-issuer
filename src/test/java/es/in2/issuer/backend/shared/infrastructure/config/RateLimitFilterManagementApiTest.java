package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-269: the issuance, revocation and query APIs have the volume limit of their requester instead of the
 * per-address one; every other route keeps it.
 */
class RateLimitFilterManagementApiTest {

    private static MockServerWebExchange post(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.post("/issuer" + path).contextPath("/issuer")
                .remoteAddress(new java.net.InetSocketAddress("10.0.0.1", 1234)).build());
    }

    @Test
    void theManagementApis_areNotLimitedByAddress() {
        RateLimitFilter filter = new RateLimitFilter(1);
        AtomicInteger calls = new AtomicInteger();
        WebFilterChain chain = exchange -> {
            calls.incrementAndGet();
            return Mono.empty();
        };

        for (int i = 0; i < 3; i++) {
            StepVerifier.create(filter.filter(post("/api/v1/issuances"), chain)).verifyComplete();
            StepVerifier.create(filter.filter(post("/api/v1/issuances/abc/revocation"), chain)).verifyComplete();
        }

        assertThat(calls).hasValue(6);
    }

    @Test
    void theManagementApis_limitByAddressTheRequestsThatFailAuthentication() {
        RateLimitFilter filter = new RateLimitFilter(2);
        WebFilterChain unauthenticated = exchange -> {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), unauthenticated)).verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/issuances/abc/revocation"), unauthenticated)).verifyComplete();
        MockServerWebExchange third = post("/api/v1/issuances");
        AtomicInteger calls = new AtomicInteger();
        StepVerifier.create(filter.filter(third, exchange -> {
            calls.incrementAndGet();
            return Mono.empty();
        })).verifyComplete();

        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(third.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("60");
        assertThat(calls).hasValue(0);
    }

    @Test
    void theOtherRoutes_keepTheLimitByAddress() {
        RateLimitFilter filter = new RateLimitFilter(1);
        WebFilterChain chain = exchange -> Mono.empty();

        MockServerWebExchange first = post("/oauth/token");
        MockServerWebExchange second = post("/oauth/token");
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertThat(first.getResponse().getStatusCode()).isNull();
        assertThat(second.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }
}
