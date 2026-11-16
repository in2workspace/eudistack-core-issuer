package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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
 * per-address one; there every request the volume limit did not count is limited per address. Every other route
 * keeps the per-address limit.
 */
class RateLimitFilterManagementApiTest {

    /** A valid token counted in the volume limit of its requester. */
    private static final WebFilterChain COUNTED = exchange -> {
        exchange.getAttributes().put(ApiVolumeLimitFilter.COUNTED_ATTRIBUTE, Boolean.TRUE);
        return Mono.empty();
    };

    /** A valid token with no requester (another tenant in X-Tenant): the decision point answers 403. */
    private static final WebFilterChain AUTHENTICATED_NOT_COUNTED = exchange -> {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
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
        return request(HttpMethod.POST, path, bearer, forwardedFor, "a");
    }

    private static MockServerWebExchange request(HttpMethod method, String path, String bearer, String forwardedFor,
                                                 String tenant) {
        MockServerHttpRequest.BodyBuilder request = MockServerHttpRequest.method(method, "/issuer" + path)
                .contextPath("/issuer")
                .remoteAddress(new java.net.InetSocketAddress("10.0.0.1", 1234))
                .header("X-Forwarded-For", forwardedFor)
                .header("X-Tenant", tenant);
        if (bearer != null) {
            request.header(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
        }
        return MockServerWebExchange.from(request.build());
    }

    @Test
    void theManagementApis_doNotLimitByAddressTheRequestsCountedByTheirRequester() {
        RateLimitFilter filter = new RateLimitFilter(1);
        AtomicInteger calls = new AtomicInteger();
        WebFilterChain chain = exchange -> {
            calls.incrementAndGet();
            return COUNTED.filter(exchange);
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
        StepVerifier.create(filter.filter(post("/api/v1/issuances", "valid-token", victim), COUNTED))
                .verifyComplete();

        for (int i = 0; i < 3; i++) {
            StepVerifier.create(filter.filter(post("/api/v1/issuances", "forged-" + i, victim), UNAUTHENTICATED))
                    .verifyComplete();
        }
        MockServerWebExchange stillValid = post("/api/v1/issuances", "valid-token", victim);
        MockServerWebExchange forged = post("/api/v1/issuances", "forged-9", victim);
        StepVerifier.create(filter.filter(stillValid, COUNTED)).verifyComplete();
        StepVerifier.create(filter.filter(forged, UNAUTHENTICATED)).verifyComplete();

        assertThat(stillValid.getResponse().getStatusCode()).isNull();
        assertThat(forged.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void aValidTokenOfAnotherTenant_isLimitedByAddress() {
        RateLimitFilter filter = new RateLimitFilter(100);
        // Counted once for its own tenant: that does not let it through for another one.
        StepVerifier.create(filter.filter(request(HttpMethod.POST, "/api/v1/issuances", "token-a", "10.0.0.9", "a"),
                COUNTED)).verifyComplete();

        for (int i = 0; i < 100; i++) {
            MockServerWebExchange exchange = request(HttpMethod.POST, "/api/v1/issuances", "token-a", "10.0.0.9", "b");
            StepVerifier.create(filter.filter(exchange, AUTHENTICATED_NOT_COUNTED)).verifyComplete();
            assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        }
        MockServerWebExchange over = request(HttpMethod.POST, "/api/v1/issuances", "token-a", "10.0.0.9", "b");
        StepVerifier.create(filter.filter(over, AUTHENTICATED_NOT_COUNTED)).verifyComplete();

        assertThat(over.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void aRouteWithoutOperation_isLimitedByAddress_evenWithAValidToken() {
        RateLimitFilter filter = new RateLimitFilter(2);
        WebFilterChain served = exchange -> Mono.empty();

        for (HttpMethod method : new HttpMethod[] {HttpMethod.PUT, HttpMethod.DELETE}) {
            StepVerifier.create(filter.filter(request(method, "/api/v1/issuances/abc", "token-a", "10.0.0.8", "a"),
                    served)).verifyComplete();
        }
        MockServerWebExchange third = request(HttpMethod.PUT, "/api/v1/issuances/abc", "token-a", "10.0.0.8", "a");
        StepVerifier.create(filter.filter(third, served)).verifyComplete();

        assertThat(third.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
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
