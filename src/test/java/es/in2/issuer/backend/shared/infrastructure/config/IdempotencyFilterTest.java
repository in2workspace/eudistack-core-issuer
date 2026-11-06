package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.exception.InvalidTokenException;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
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

import com.fasterxml.jackson.databind.ObjectMapper;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Sinks;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IdempotencyFilterTest {

    private static final String IDEMPOTENCY_HEADER = "X-Idempotency-Key";
    private static final String TENANT_HEADER = "X-Tenant";
    private static final String BODY = "{\"signed_credential\":\"signed-jwt\"}";

    @Mock
    private IssuanceMetrics issuanceMetrics;

    @Mock
    private AccessTokenService accessTokenService;

    private IdempotencyFilter filter;

    @BeforeEach
    void setUp() {
        filter = newFilter(Duration.ofSeconds(30));
        // Default: caller resolves to a single organization and subject from the authenticated
        // SecurityContext. Tests exercising scoping or failure override this.
        lenient().when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.just("org-a"));
        lenient().when(accessTokenService.getSubjectFromCurrentSession())
                .thenReturn(Mono.just("sub-a"));
    }

    private IdempotencyFilter newFilter(Duration waitTimeout) {
        return new IdempotencyFilter(3600, waitTimeout, issuanceMetrics, accessTokenService,
                new ErrorResponseFactory(), new ObjectMapper());
    }

    private static MockServerWebExchange post(String key, String body) {
        return MockServerWebExchange.from(MockServerHttpRequest.post(ISSUANCES_PATH)
                .header(IDEMPOTENCY_HEADER, key)
                .body(body));
    }

    /** Chain whose first invocation waits for the gate; answers with a Location and the fixed body. */
    private WebFilterChain gatedChain(AtomicInteger invocations, Sinks.Empty<Void> gate, HttpStatus firstStatus) {
        return exchange -> {
            int n = invocations.incrementAndGet();
            Mono<Void> wait = n == 1 ? gate.asMono() : Mono.empty();
            return wait.then(Mono.defer(() -> {
                exchange.getResponse().setStatusCode(n == 1 ? firstStatus : HttpStatus.OK);
                exchange.getResponse().getHeaders().setLocation(URI.create("https://issuer.example.com/p/1"));
                exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                DataBuffer buffer = new DefaultDataBufferFactory().wrap(BODY.getBytes(StandardCharsets.UTF_8));
                return exchange.getResponse().writeWith(Mono.just(buffer));
            }));
        };
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
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();
        assertEquals(BODY, readBody(first));

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(BODY, readBody(second));
        assertEquals(HttpStatus.OK, second.getResponse().getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, second.getResponse().getHeaders().getContentType());
        assertEquals(1, invocations.get());
        verify(issuanceMetrics).recordIdempotencyCacheHit();
    }

    @Test
    void requestUnderTheContextPath_isCachedAndReplaysStatusBodyAndLocation() {
        String key = "idem-key-context-path";
        AtomicInteger invocations = new AtomicInteger();
        String location = "https://issuer.example.com/issuer" + ISSUANCES_PATH + "/abc";
        WebFilterChain chain = exchange -> {
            exchange.getResponse().getHeaders().setLocation(URI.create(location));
            return writingChain(invocations).filter(exchange);
        };

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post("/issuer" + ISSUANCES_PATH)
                        .contextPath("/issuer")
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post("/issuer" + ISSUANCES_PATH)
                        .contextPath("/issuer")
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(1, invocations.get());
        assertEquals(HttpStatus.OK, second.getResponse().getStatusCode());
        assertEquals(BODY, readBody(second));
        assertEquals(location, second.getResponse().getHeaders().getFirst("Location"));
        verify(issuanceMetrics).recordIdempotencyCacheHit();
    }

    @Test
    void getWithTheKey_isNotCached() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        for (int i = 0; i < 2; i++) {
            MockServerWebExchange exchange = MockServerWebExchange.from(
                    MockServerHttpRequest.get(ISSUANCES_PATH)
                            .header(IDEMPOTENCY_HEADER, "idem-key-get")
                            .build());
            StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        }

        assertEquals(2, invocations.get());
        verify(issuanceMetrics, never()).recordIdempotencyCacheHit();
    }

    @Test
    void sameKeyDifferentTenants_doesNotCollide() {
        String sharedKey = "shared-idem-key";
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange tenantA = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header("X-Tenant", "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(tenantA, chain)).verifyComplete();

        MockServerWebExchange tenantB = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header("X-Tenant", "tenant-b")
                        .build());
        StepVerifier.create(filter.filter(tenantB, chain)).verifyComplete();

        // Different tenants reusing the same idempotency key (same organization) must NOT share the cache entry.
        assertEquals(2, invocations.get());
        assertEquals(BODY, readBody(tenantB));
    }

    @Test
    void sameKeyDifferentOrganizationsSameTenant_doesNotCollide() {
        // Regression test for H2: same tenant, same idempotency key, but two different
        // organizations -- reusing a key across organizations of the same tenant must not
        // return one organization's cached response (e.g. a signed credential) to the other.
        String sharedKey = "shared-idem-key";
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);
        when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.just("org-a"), Mono.just("org-b"));

        MockServerWebExchange orgA = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header(TENANT_HEADER, "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(orgA, chain)).verifyComplete();

        MockServerWebExchange orgB = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, sharedKey)
                        .header(TENANT_HEADER, "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(orgB, chain)).verifyComplete();

        assertEquals(2, invocations.get());
        assertEquals(BODY, readBody(orgB));
        verify(issuanceMetrics, never()).recordIdempotencyCacheHit();
    }

    @Test
    void unresolvableSession_bypassesCacheGracefully() {
        // Covers both a missing/anonymous SecurityContext and a session whose token cannot be
        // resolved (W3, code-review): the organization now comes from the already-authenticated
        // SecurityContext rather than a fresh, unverified parse of the Authorization header, so
        // both cases collapse into the same "cannot resolve caller organization" fallback.
        String key = "unresolvable-session-key";
        when(accessTokenService.getOrganizationIdFromCurrentSession())
                .thenReturn(Mono.error(new InvalidTokenException()));
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, key)
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        // A session that cannot be resolved must not crash the request nor be cached under a wrong key.
        assertEquals(2, invocations.get());
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
    void sameKeyDifferentTenants_invokeChainEachTime() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        MockServerWebExchange first = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, "same-key")
                        .header(TENANT_HEADER, "tenant-a")
                        .build());
        StepVerifier.create(filter.filter(first, chain)).verifyComplete();

        MockServerWebExchange second = MockServerWebExchange.from(
                MockServerHttpRequest.post(ISSUANCES_PATH)
                        .header(IDEMPOTENCY_HEADER, "same-key")
                        .header(TENANT_HEADER, "tenant-b")
                        .build());
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(2, invocations.get());
    }

    @Test
    void sameKeyDifferentSubjectSameTenantAndOrganization_isNotReplayed() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);
        when(accessTokenService.getSubjectFromCurrentSession())
                .thenReturn(Mono.just("sub-a"), Mono.just("sub-b"));

        StepVerifier.create(filter.filter(post("shared-key", BODY), chain)).verifyComplete();
        StepVerifier.create(filter.filter(post("shared-key", BODY), chain)).verifyComplete();

        assertEquals(2, invocations.get());
        verify(issuanceMetrics, never()).recordIdempotencyCacheHit();
    }

    @Test
    void sameKeyDifferentBody_answers422Problem_andDoesNotReachTheChain() {
        AtomicInteger invocations = new AtomicInteger();
        WebFilterChain chain = writingChain(invocations);

        StepVerifier.create(filter.filter(post("key-body", "{\"a\":1}"), chain)).verifyComplete();
        MockServerWebExchange second = post("key-body", "{\"a\":2}");
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(1, invocations.get());
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, second.getResponse().getStatusCode());
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, second.getResponse().getHeaders().getContentType());
        assertTrue(readBody(second).contains("\"type\":\"idempotency_key_reused\""));
    }

    @Test
    void theRawKeyIsNeverLogged() {
        String rawKey = "super-secret-idempotency-key";
        Logger logger = (Logger) LoggerFactory.getLogger(IdempotencyFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            WebFilterChain chain = writingChain(new AtomicInteger());
            StepVerifier.create(filter.filter(post(rawKey, "{\"a\":1}"), chain)).verifyComplete();
            StepVerifier.create(filter.filter(post(rawKey, "{\"a\":1}"), chain)).verifyComplete();
            StepVerifier.create(filter.filter(post(rawKey, "{\"a\":2}"), chain)).verifyComplete();

            assertFalse(appender.list.isEmpty());
            assertTrue(appender.list.stream().noneMatch(e -> e.getFormattedMessage().contains(rawKey)));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void concurrentDuplicate_waitsForTheFirst_andGetsTheSameResponse() throws Exception {
        AtomicInteger invocations = new AtomicInteger();
        Sinks.Empty<Void> gate = Sinks.empty();
        WebFilterChain chain = gatedChain(invocations, gate, HttpStatus.OK);
        MockServerWebExchange first = post("key-conc", BODY);
        MockServerWebExchange second = post("key-conc", BODY);

        CompletableFuture<Void> f1 = filter.filter(first, chain).toFuture();
        CompletableFuture<Void> f2 = filter.filter(second, chain).toFuture();
        assertEquals(1, invocations.get());
        assertFalse(f2.isDone());
        gate.tryEmitEmpty();
        f1.get(5, TimeUnit.SECONDS);
        f2.get(5, TimeUnit.SECONDS);

        assertEquals(1, invocations.get());
        assertEquals(HttpStatus.OK, second.getResponse().getStatusCode());
        assertEquals(readBody(first), readBody(second));
        assertEquals("https://issuer.example.com/p/1", first.getResponse().getHeaders().getFirst("Location"));
        assertEquals(first.getResponse().getHeaders().getFirst("Location"),
                second.getResponse().getHeaders().getFirst("Location"));
    }

    @Test
    void concurrentDuplicateWithDifferentBody_answers422_withoutWaiting() {
        AtomicInteger invocations = new AtomicInteger();
        Sinks.Empty<Void> gate = Sinks.empty();
        WebFilterChain chain = gatedChain(invocations, gate, HttpStatus.OK);

        CompletableFuture<Void> f1 = filter.filter(post("key-conc-body", "{\"a\":1}"), chain).toFuture();
        MockServerWebExchange second = post("key-conc-body", "{\"a\":2}");
        StepVerifier.create(filter.filter(second, chain)).verifyComplete();

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, second.getResponse().getStatusCode());
        assertEquals(1, invocations.get());
        gate.tryEmitEmpty();
        assertTrue(f1.isDone());
    }

    @Test
    void firstFails_theWaiterProceedsThroughTheChain() throws Exception {
        AtomicInteger invocations = new AtomicInteger();
        Sinks.Empty<Void> gate = Sinks.empty();
        WebFilterChain chain = gatedChain(invocations, gate, HttpStatus.INTERNAL_SERVER_ERROR);
        MockServerWebExchange first = post("key-fail", BODY);
        MockServerWebExchange second = post("key-fail", BODY);

        CompletableFuture<Void> f1 = filter.filter(first, chain).toFuture();
        CompletableFuture<Void> f2 = filter.filter(second, chain).toFuture();
        gate.tryEmitEmpty();
        f1.get(5, TimeUnit.SECONDS);
        f2.get(5, TimeUnit.SECONDS);

        assertEquals(2, invocations.get());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, first.getResponse().getStatusCode());
        assertEquals(HttpStatus.OK, second.getResponse().getStatusCode());
        verify(issuanceMetrics, never()).recordIdempotencyCacheHit();
    }

    @Test
    void waitTimeout_answers409WithRetryAfter() throws Exception {
        filter = newFilter(Duration.ofMillis(50));
        AtomicInteger invocations = new AtomicInteger();
        Sinks.Empty<Void> gate = Sinks.empty();
        WebFilterChain chain = gatedChain(invocations, gate, HttpStatus.OK);

        CompletableFuture<Void> f1 = filter.filter(post("key-timeout", BODY), chain).toFuture();
        MockServerWebExchange second = post("key-timeout", BODY);
        filter.filter(second, chain).toFuture().get(5, TimeUnit.SECONDS);

        assertEquals(HttpStatus.CONFLICT, second.getResponse().getStatusCode());
        assertEquals("1", second.getResponse().getHeaders().getFirst("Retry-After"));
        assertEquals(MediaType.APPLICATION_PROBLEM_JSON, second.getResponse().getHeaders().getContentType());
        assertTrue(readBody(second).contains("\"type\":\"idempotency_request_in_progress\""));
        assertEquals(1, invocations.get());
        gate.tryEmitEmpty();
        f1.get(5, TimeUnit.SECONDS);
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
