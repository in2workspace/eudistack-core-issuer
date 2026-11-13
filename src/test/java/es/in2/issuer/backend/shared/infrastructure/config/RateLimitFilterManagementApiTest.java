package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
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
 * per-address one; there only the requests that end without a verified credential are limited per address.
 * Every other route keeps the per-address limit.
 */
class RateLimitFilterManagementApiTest {

    private static final WebFilterChain AUTHENTICATED = exchange -> {
        exchange.getAttributes().put(RateLimitFilter.AUTHENTICATED_ATTRIBUTE, Boolean.TRUE);
        return Mono.empty();
    };

    private static final WebFilterChain UNAUTHENTICATED = exchange -> {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return Mono.empty();
    };

    private static MockServerWebExchange post(String path) {
        return post(path, null, "10.0.0.1");
    }

    private static MockServerWebExchange post(String path, String bearer, String forwardedFor) {
        MockServerHttpRequest.BodyBuilder request = MockServerHttpRequest.post("/issuer" + path).contextPath("/issuer")
                .remoteAddress(new java.net.InetSocketAddress("10.0.0.1", 1234))
                .header("X-Forwarded-For", forwardedFor);
        if (bearer != null) {
            request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        }
        return MockServerWebExchange.from(request.build());
    }

    @Test
    void theManagementApis_doNotLimitByAddressTheAuthenticatedRequests() {
        RateLimitFilter filter = new RateLimitFilter(1);
        AtomicInteger calls = new AtomicInteger();
        WebFilterChain chain = exchange -> {
            calls.incrementAndGet();
            return AUTHENTICATED.filter(exchange);
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

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), UNAUTHENTICATED)).verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/issuances/abc/revocation"), UNAUTHENTICATED)).verifyComplete();
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
    void theManagementApis_countEveryRequestThatEndsWithoutAVerifiedCredential_notOnlyThe401() {
        RateLimitFilter filter = new RateLimitFilter(2);
        // The verifier's metadata could not be read: the token was never verified, and it cost a remote call.
        WebFilterChain verifierDown = exchange -> {
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return Mono.empty();
        };
        WebFilterChain failing = exchange -> Mono.error(new IllegalStateException("Error fetching metadata"));

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), verifierDown)).verifyComplete();
        StepVerifier.create(filter.filter(post("/api/v1/issuances"), failing)).verifyError(IllegalStateException.class);
        MockServerWebExchange third = post("/api/v1/issuances");
        StepVerifier.create(filter.filter(third, verifierDown)).verifyComplete();

        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void aFloodOfInvalidTokensNamingAnotherAddress_doesNotLockOutACredentialThatAlreadyAuthenticated() {
        RateLimitFilter filter = new RateLimitFilter(2);
        String victim = "203.0.113.7";
        StepVerifier.create(filter.filter(post("/api/v1/issuances", "valid-token", victim), AUTHENTICATED))
                .verifyComplete();

        for (int i = 0; i < 3; i++) {
            StepVerifier.create(filter.filter(post("/api/v1/issuances", "forged-" + i, victim), UNAUTHENTICATED))
                    .verifyComplete();
        }
        MockServerWebExchange stillValid = post("/api/v1/issuances", "valid-token", victim);
        MockServerWebExchange forged = post("/api/v1/issuances", "forged-9", victim);
        StepVerifier.create(filter.filter(stillValid, AUTHENTICATED)).verifyComplete();
        StepVerifier.create(filter.filter(forged, UNAUTHENTICATED)).verifyComplete();

        assertThat(stillValid.getResponse().getStatusCode()).isNull();
        assertThat(forged.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
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
