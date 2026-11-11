package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.IdempotencyClaim;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.StoredResponse;
import es.in2.issuer.backend.shared.domain.service.IdempotencyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.ISSUANCES_PATH;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IdempotencyFilterTest {

    private static final String KEY = "retry-key-1";
    private static final String REQUEST_BODY = "{\"credential_configuration_id\":\"x\"}";
    private static final String RESPONSE_BODY = "{\"responses\":[{\"channel\":\"ui\",\"status\":200}]}";
    private static final Requester REQUESTER = Requester.system("ORG-1");
    private static final int MAX_BODY_BYTES = 1024;
    private static final IdempotencyClaim.Acquired ACQUIRED = new IdempotencyClaim.Acquired("scope", "owner");

    @Mock
    private RequesterResolver requesterResolver;
    @Mock
    private IdempotencyService idempotencyService;
    @Mock
    private IssuanceMetrics issuanceMetrics;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private IdempotencyFilter filter;

    @BeforeEach
    void setUp() {
        filter = new IdempotencyFilter(requesterResolver, idempotencyService, new FilterProblemWriter(objectMapper),
                issuanceMetrics, MAX_BODY_BYTES);
        lenient().when(requesterResolver.current()).thenReturn(Mono.just(REQUESTER));
        lenient().when(idempotencyService.complete(any(), any())).thenReturn(Mono.empty());
        lenient().when(idempotencyService.release(any())).thenReturn(Mono.empty());
    }

    private static MockServerWebExchange issuance(String key) {
        MockServerHttpRequest.BodyBuilder request = MockServerHttpRequest.post("/issuer" + ISSUANCES_PATH)
                .contextPath("/issuer")
                .contentType(MediaType.APPLICATION_JSON);
        if (key != null) {
            request.header(IdempotencyFilter.IDEMPOTENCY_HEADER, key);
        }
        return MockServerWebExchange.from(request.body(REQUEST_BODY));
    }

    /** A controller that reads the request body and answers with {@code status}. */
    private static WebFilterChain controller(HttpStatus status, AtomicInteger calls, AtomicReference<String> bodyRead) {
        return exchange -> DataBufferUtils.join(exchange.getRequest().getBody())
                .map(buffer -> buffer.toString(StandardCharsets.UTF_8))
                .defaultIfEmpty("")
                .flatMap(body -> {
                    calls.incrementAndGet();
                    bodyRead.set(body);
                    exchange.getResponse().setStatusCode(status);
                    exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    exchange.getResponse().getHeaders().setLocation(URI.create("/api/v1/issuances/42"));
                    return exchange.getResponse().writeWith(Mono.just(
                            new DefaultDataBufferFactory().wrap(RESPONSE_BODY.getBytes(StandardCharsets.UTF_8))));
                });
    }

    private JsonNode problem(MockServerWebExchange exchange) throws Exception {
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        return objectMapper.readTree(exchange.getResponse().getBodyAsString().block());
    }

    @Test
    void firstRequest_isProcessed_andItsSuccessfulResponseIsStoredBeforeItIsSent() {
        when(idempotencyService.claim(REQUESTER, KEY, REQUEST_BODY.getBytes(StandardCharsets.UTF_8)))
                .thenReturn(Mono.just(ACQUIRED));
        AtomicInteger calls = new AtomicInteger();
        AtomicReference<String> bodyRead = new AtomicReference<>();
        MockServerWebExchange exchange = issuance(KEY);

        StepVerifier.create(filter.filter(exchange, controller(HttpStatus.OK, calls, bodyRead))).verifyComplete();

        assertThat(calls).hasValue(1);
        assertThat(bodyRead.get()).isEqualTo(REQUEST_BODY);
        assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo(RESPONSE_BODY);
        ArgumentCaptor<StoredResponse> stored = ArgumentCaptor.forClass(StoredResponse.class);
        verify(idempotencyService).complete(eq(ACQUIRED), stored.capture());
        assertThat(stored.getValue().status()).isEqualTo(200);
        assertThat(stored.getValue().location()).isEqualTo("/api/v1/issuances/42");
        assertThat(stored.getValue().contentType()).isEqualTo("application/json");
        assertThat(new String(stored.getValue().body(), StandardCharsets.UTF_8)).isEqualTo(RESPONSE_BODY);
        verify(idempotencyService, never()).release(any());
    }

    @Test
    void errorResponse_isNotStored_theKeyIsFreed() {
        when(idempotencyService.claim(any(), anyString(), any())).thenReturn(Mono.just(ACQUIRED));
        MockServerWebExchange exchange = issuance(KEY);

        StepVerifier.create(filter.filter(exchange,
                controller(HttpStatus.SERVICE_UNAVAILABLE, new AtomicInteger(), new AtomicReference<>()))).verifyComplete();

        verify(idempotencyService).release(ACQUIRED);
        verify(idempotencyService, never()).complete(any(), any());
    }

    @Test
    void exceptionInTheChain_freesTheKeyAndPropagates() {
        when(idempotencyService.claim(any(), anyString(), any())).thenReturn(Mono.just(ACQUIRED));

        StepVerifier.create(filter.filter(issuance(KEY), ex -> Mono.error(new IllegalStateException("boom"))))
                .verifyError(IllegalStateException.class);

        verify(idempotencyService).release(ACQUIRED);
    }

    @Test
    void sameKeyAndBody_returnsTheStoredResponseWithoutProcessingAgain() {
        StoredResponse stored = new StoredResponse(200, "application/json", "/api/v1/issuances/42",
                RESPONSE_BODY.getBytes(StandardCharsets.UTF_8));
        when(idempotencyService.claim(any(), anyString(), any())).thenReturn(Mono.just(new IdempotencyClaim.Replay(stored)));
        AtomicInteger calls = new AtomicInteger();
        MockServerWebExchange exchange = issuance(KEY);

        StepVerifier.create(filter.filter(exchange, controller(HttpStatus.OK, calls, new AtomicReference<>()))).verifyComplete();

        assertThat(calls).hasValue(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(exchange.getResponse().getHeaders().getLocation()).hasToString("/api/v1/issuances/42");
        assertThat(exchange.getResponse().getBodyAsString().block()).isEqualTo(RESPONSE_BODY);
        verify(issuanceMetrics).recordIdempotencyCacheHit();
    }

    @Test
    void sameKeyWhileInProgress_is409IdempotencyInProgress() throws Exception {
        when(idempotencyService.claim(any(), anyString(), any())).thenReturn(Mono.just(new IdempotencyClaim.InProgress()));
        MockServerWebExchange exchange = issuance(KEY);

        StepVerifier.create(filter.filter(exchange, ex -> Mono.error(new AssertionError("must not run")))).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(problem(exchange).path("type").asText()).isEqualTo("idempotency_in_progress");
        assertThat(exchange.getResponse().getHeaders().getFirst("Retry-After")).isEqualTo("1");
    }

    @Test
    void bodyOverThePayloadLimit_is413_withoutClaimingTheKey() throws Exception {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                .post("/issuer" + ISSUANCES_PATH).contextPath("/issuer")
                .contentType(MediaType.APPLICATION_JSON)
                .header(IdempotencyFilter.IDEMPOTENCY_HEADER, KEY)
                .body("{\"x\":\"" + "a".repeat(MAX_BODY_BYTES) + "\"}"));

        StepVerifier.create(filter.filter(exchange, ex -> Mono.error(new AssertionError("must not run")))).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.PAYLOAD_TOO_LARGE);
        assertThat(problem(exchange).path("type").asText()).isEqualTo("payload_too_large");
        verifyNoInteractions(idempotencyService);
    }

    @Test
    void sameKeyOtherBody_is422IdempotencyKeyReused() throws Exception {
        when(idempotencyService.claim(any(), anyString(), any())).thenReturn(Mono.just(new IdempotencyClaim.KeyReused()));
        MockServerWebExchange exchange = issuance(KEY);

        StepVerifier.create(filter.filter(exchange, ex -> Mono.error(new AssertionError("must not run")))).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        JsonNode problem = problem(exchange);
        assertThat(problem.path("type").asText()).isEqualTo("idempotency_key_reused");
        assertThat(problem.path("status").asInt()).isEqualTo(422);
        assertThat(problem.path("instance").asText()).isEqualTo("/issuer" + ISSUANCES_PATH);
    }

    @Test
    void keyLongerThanTheContractAllows_is400() throws Exception {
        MockServerWebExchange exchange = issuance("k".repeat(IdempotencyFilter.MAX_KEY_LENGTH + 1));

        StepVerifier.create(filter.filter(exchange, ex -> Mono.error(new AssertionError("must not run")))).verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode problem = problem(exchange);
        assertThat(problem.path("type").asText()).isEqualTo("BAD_REQUEST");
        assertThat(problem.path("violations").get(0).path("field").asText()).isEqualTo("X-Idempotency-Key");
        verifyNoInteractions(idempotencyService);
    }

    @Test
    void withoutKey_otherRouteOrMethod_orWithoutRequester_isNotHandled() {
        AtomicInteger calls = new AtomicInteger();
        WebFilterChain chain = controller(HttpStatus.OK, calls, new AtomicReference<>());

        StepVerifier.create(filter.filter(issuance(null), chain)).verifyComplete();
        StepVerifier.create(filter.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/issuer" + ISSUANCES_PATH)
                .contextPath("/issuer").header(IdempotencyFilter.IDEMPOTENCY_HEADER, KEY).build()), chain)).verifyComplete();
        when(requesterResolver.current()).thenReturn(Mono.empty());
        StepVerifier.create(filter.filter(issuance(KEY), chain)).verifyComplete();

        assertThat(calls).hasValue(3);
        verify(idempotencyService, never()).claim(any(), anyString(), any());
    }

    @Test
    void pathIsMatchedWithinTheApplication_soTheBasePathDoesNotDisableIt() {
        when(idempotencyService.claim(any(), anyString(), any())).thenReturn(Mono.just(new IdempotencyClaim.InProgress()));
        MockServerWebExchange exchange = issuance(KEY);

        StepVerifier.create(filter.filter(exchange, ex -> Mono.empty())).verifyComplete();

        // TD-03 of EUD-254: comparing the full path ("/issuer/api/v1/issuances") never matched.
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(List.of(filter.getOrder())).containsExactly(IdempotencyFilter.ORDER);
        assertThat(IdempotencyFilter.ORDER).isGreaterThan(ApiVolumeLimitFilter.ORDER)
                .isGreaterThan(TenantDomainWebFilter.ORDER);
    }
}
