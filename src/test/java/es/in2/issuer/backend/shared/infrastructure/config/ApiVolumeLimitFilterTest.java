package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitDecision;
import es.in2.issuer.backend.shared.domain.service.VolumeLimitService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ApiVolumeLimitFilterTest {

    private static final Requester SYSTEM = Requester.system("sandbox", "VATES-A15456585", null);

    @Mock
    private RequesterResolver requesterResolver;
    @Mock
    private VolumeLimitService volumeLimitService;
    @Mock
    private IssuanceMetrics metrics;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private ApiVolumeLimitFilter filter;
    private final AtomicInteger calls = new AtomicInteger();
    private final WebFilterChain chain = exchange -> {
        calls.incrementAndGet();
        return Mono.empty();
    };

    @BeforeEach
    void setUp() {
        filter = new ApiVolumeLimitFilter(requesterResolver, volumeLimitService, new FilterProblemWriter(objectMapper), metrics);
        lenient().when(requesterResolver.current()).thenReturn(Mono.just(SYSTEM));
    }

    private static MockServerWebExchange post(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.post("/issuer" + path).contextPath("/issuer").build());
    }

    @Test
    void withinTheLimit_goesOn() {
        when(volumeLimitService.check(ApiOperation.ISSUANCE, SYSTEM)).thenReturn(Mono.just(VolumeLimitDecision.allowed(300)));

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), chain)).verifyComplete();

        assertThat(calls).hasValue(1);
    }

    @Test
    void overTheLimit_is429RateLimitedProblemWithRetryAfter_andNothingElseRuns() throws Exception {
        when(volumeLimitService.check(ApiOperation.REVOCATION, SYSTEM))
                .thenReturn(Mono.just(VolumeLimitDecision.rejected(300, 17)));
        MockServerWebExchange exchange = post("/api/v1/issuances/0b0d7b38-4bf8-4c2b-9a6f-5a3a07a3f8a1/revocation");

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertThat(calls).hasValue(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("17");
        assertThat(exchange.getResponse().getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        JsonNode problem = objectMapper.readTree(exchange.getResponse().getBodyAsString().block());
        assertThat(problem.path("type").asText()).isEqualTo("rate_limited");
        assertThat(problem.path("status").asInt()).isEqualTo(429);
        verify(metrics).recordVolumeLimitRejection("revocation", "system");
    }

    @Test
    void aRouteWithoutVolumeLimit_isNotCounted() {
        StepVerifier.create(filter.filter(post("/oauth/token"), chain)).verifyComplete();

        assertThat(calls).hasValue(1);
        verifyNoInteractions(requesterResolver, volumeLimitService);
    }

    @Test
    void aRequestThatNamesNoOrganization_isNotCounted() {
        when(requesterResolver.current()).thenReturn(Mono.empty());

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), chain)).verifyComplete();

        assertThat(calls).hasValue(1);
        verify(volumeLimitService, never()).check(any(), any());
    }

    @Test
    void countersUnavailable_failsOpen() {
        when(volumeLimitService.check(any(), any())).thenReturn(Mono.error(new IllegalStateException("db down")));

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), chain)).verifyComplete();

        assertThat(calls).hasValue(1);
    }

    @Test
    void anErrorOfTheControllerIsNotSwallowed() {
        when(volumeLimitService.check(any(), any())).thenReturn(Mono.just(VolumeLimitDecision.allowed(300)));

        StepVerifier.create(filter.filter(post("/api/v1/issuances"), ex -> Mono.error(new IllegalStateException("boom"))))
                .verifyError(IllegalStateException.class);
    }

    @Test
    void runsAfterTheTenantIsResolved() {
        assertThat(filter.getOrder()).isGreaterThan(TenantDomainWebFilter.ORDER);
    }
}
