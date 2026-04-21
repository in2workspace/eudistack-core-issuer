package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.service.TenantRegistryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_ID_HEADER;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TenantDomainWebFilterTest {

    private TenantRegistryService tenantRegistryService;
    private TenantDomainWebFilter filter;

    @BeforeEach
    void setUp() {
        tenantRegistryService = mock(TenantRegistryService.class);
        filter = new TenantDomainWebFilter(tenantRegistryService);
    }

    @Test
    void filter_headerPresent_resolvesFromHeaderAndWritesContext() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("altia")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://altia.eudistack.net/issuer/ping")
                        .header(TENANT_ID_HEADER, "altia"));
        AtomicReference<String> captured = new AtomicReference<>();
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals("altia", captured.get());
    }

    @Test
    void filter_headerAbsent_extractsTenantFromHost() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("kpmg")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://kpmg.eudistack.net/issuer/ping"));
        AtomicReference<String> captured = new AtomicReference<>();
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals("kpmg", captured.get());
    }

    @Test
    void filter_headerAndHostPresent_headerTakesPrecedence() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("altia")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://kpmg.eudistack.net/issuer/ping")
                        .header(TENANT_ID_HEADER, "altia"));
        AtomicReference<String> captured = new AtomicReference<>();
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals("altia", captured.get());
    }

    @Test
    void filter_noHeaderAndBlankHost_passesThroughWithoutTenant() {
        MockServerHttpRequest request = MockServerHttpRequest.method(
                org.springframework.http.HttpMethod.GET, "/actuator/health").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicReference<String> captured = new AtomicReference<>("untouched");
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertNull(captured.get());
    }

    @Test
    void filter_tenantNotRegistered_returns404() {
        when(tenantRegistryService.getActiveTenantSchemas()).thenReturn(Mono.just(List.of("altia")));
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://unknown.eudistack.net/issuer/ping"));
        WebFilterChain chain = ex -> Mono.error(new AssertionError("chain must not be invoked"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals(HttpStatus.NOT_FOUND, exchange.getResponse().getStatusCode());
    }

    @Test
    void filter_malformedHeaderValue_returns400() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://altia.eudistack.net/issuer/ping")
                        .header(TENANT_ID_HEADER, "bad tenant!"));
        WebFilterChain chain = ex -> Mono.error(new AssertionError("chain must not be invoked"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals(HttpStatus.BAD_REQUEST, exchange.getResponse().getStatusCode());
    }

    @Test
    void filter_bootstrapPath_bypassesFilterEvenWithoutTenantHeaderOrHost() {
        // Bootstrap is a cross-tenant admin endpoint: the caller may have no
        // tenant header and an arbitrary host. The filter must not interfere —
        // the bootstrap handler reads the tenant from the request body.
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/v1/bootstrap").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        AtomicReference<String> captured = new AtomicReference<>("untouched");
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        // Chain was invoked (no 400/404), and no tenant was written to context.
        assertNull(captured.get());
    }

    @Test
    void filter_bootstrapPath_ignoresMalformedTenantHeader() {
        // Even if a caller happens to send X-Tenant-Id on bootstrap, the
        // filter must not validate it — the body is the source of truth.
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/bootstrap")
                        .header(TENANT_ID_HEADER, "bad tenant!"));
        AtomicReference<Boolean> chainInvoked = new AtomicReference<>(false);
        WebFilterChain chain = ex -> {
            chainInvoked.set(true);
            return Mono.empty();
        };

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals(true, chainInvoked.get());
    }
}
