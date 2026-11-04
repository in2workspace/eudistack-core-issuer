package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitFilterTest {

    private static final String PATH = "/api/v1/issuances/0b6f1d2e-8c4a-4b1f-9e2d-7a5c3f8e1b90/credential-offer";

    private final AtomicInteger passed = new AtomicInteger();
    private final WebFilterChain chain = exchange -> {
        passed.incrementAndGet();
        return Mono.empty();
    };

    @Test
    void RateLimitFilter_filter_passesRequestsWithinTheLimit() {
        RateLimitFilter filter = new RateLimitFilter(2);

        StepVerifier.create(filter.filter(post("10.0.0.1"), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post("10.0.0.1"), chain)).verifyComplete();

        assertThat(passed).hasValue(2);
    }

    /** AC-09: past the limit, 429 rate_limited as problem+json with Retry-After, and the request stops. */
    @Test
    void RateLimitFilter_filter_overTheLimitIsRateLimitedProblem() {
        RateLimitFilter filter = new RateLimitFilter(1);
        StepVerifier.create(filter.filter(post("10.0.0.1"), chain)).verifyComplete();

        MockServerWebExchange rejected = post("10.0.0.1");
        StepVerifier.create(filter.filter(rejected, chain)).verifyComplete();

        assertThat(passed).hasValue(1);
        assertThat(rejected.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(rejected.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(rejected.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("60");
        StepVerifier.create(rejected.getResponse().getBodyAsString())
                .assertNext(body -> assertThat(body)
                        .contains("\"type\":\"rate_limited\"")
                        .contains("\"status\":429")
                        .contains("\"title\":"))
                .verifyComplete();
    }

    /** N3: the 429 is written before Spring Security's header writer, so it sets its own. */
    @Test
    void RateLimitFilter_filter_overTheLimitIsNotSniffedNorCached() {
        RateLimitFilter filter = new RateLimitFilter(1);
        StepVerifier.create(filter.filter(post("10.0.0.2"), chain)).verifyComplete();

        MockServerWebExchange rejected = post("10.0.0.2");
        StepVerifier.create(filter.filter(rejected, chain)).verifyComplete();

        assertThat(rejected.getResponse().getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(rejected.getResponse().getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test
    void RateLimitFilter_filter_countsEachIpApart() {
        RateLimitFilter filter = new RateLimitFilter(1);

        StepVerifier.create(filter.filter(post("10.0.0.1"), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post("10.0.0.2"), chain)).verifyComplete();

        assertThat(passed).hasValue(2);
    }

    @Test
    void RateLimitFilter_filter_neverLimitsGet() {
        RateLimitFilter filter = new RateLimitFilter(0);

        StepVerifier.create(filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get(PATH)), chain))
                .verifyComplete();

        assertThat(passed).hasValue(1);
    }

    private static MockServerWebExchange post(String ip) {
        return MockServerWebExchange.from(MockServerHttpRequest.post(PATH).header("X-Forwarded-For", ip));
    }
}
