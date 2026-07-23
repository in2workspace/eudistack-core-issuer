package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class IdempotencyFilterTest {

    private static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";
    private static final String BODY = "{\"signed_credential\":\"signed-jwt\"}";

    @Mock
    private IssuanceMetrics issuanceMetrics;

    private IdempotencyFilter filter;

    @BeforeEach
    void setUp() {
        filter = new IdempotencyFilter(3600, issuanceMetrics);
    }

    /** Chain that writes a fixed JSON body once and counts how many times it runs. */
    private WebFilterChain writingChain(AtomicInteger invocations) {
        return exchange -> {
            invocations.incrementAndGet();
            exchange.getResponse().setStatusCode(HttpStatus.OK);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            DataBuffer buffer = new DefaultDataBufferFactory().wrap(BODY.getBytes(StandardCharsets.UTF_8));
            return exchange.getResponse().writeWith(Mono.just(buffer));
        };
    }

    private String readBody(MockServerWebExchange exchange) {
        return exchange.getResponse().getBodyAsString().block();
    }

    @Test
    void replayWithSameKey_returnsCachedBody_andInvokesChainOnce() {
        String key = "idem-key-1";
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).header(IDEMPOTENCY_HEADER, key).build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();
        assertEquals(BODY, readBody(first));

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).header(IDEMPOTENCY_HEADER, key).build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(BODY, readBody(second));
        assertEquals(HttpStatus.OK, second.getResponse().getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, second.getResponse().getHeaders().getContentType());
        assertEquals(1, invocations.get());
        verify(issuanceMetrics).recordIdempotencyCacheHit();
    }

    @Test
    void differentKeys_invokeChainEachTime() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).header(IDEMPOTENCY_HEADER, "key-a").build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).header(IDEMPOTENCY_HEADER, "key-b").build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(2, invocations.get());
    }

    @Test
    void noIdempotencyKey_bypassesCache() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH).build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(2, invocations.get());
    }
}
