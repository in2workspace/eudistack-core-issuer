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
    void filter_bootstrapPath_requiresTenantHeader() {
        // Bootstrap now uses the same X-Tenant-Id convention as the rest of the API.
        // With a valid header, the filter writes the tenant to the Reactor context.
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/v1/bootstrap")
                .header(TENANT_ID_HEADER, "sandbox")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        when(tenantRegistryService.getActiveTenantSchemas())
                .thenReturn(Mono.just(java.util.List.of("sandbox", "dome", "kpmg")));
        AtomicReference<String> captured = new AtomicReference<>("untouched");
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals("sandbox", captured.get());
    }

    @Test
    void filter_bootstrapPath_rejectsMalformedTenantHeader() {
        // Malformed X-Tenant-Id is rejected with 400 (same as any other endpoint).
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/api/v1/bootstrap")
                        .header(TENANT_ID_HEADER, "bad tenant!"));
        WebFilterChain chain = ex -> Mono.error(new AssertionError("chain must not be invoked"));

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertEquals(HttpStatus.BAD_REQUEST, exchange.getResponse().getStatusCode());
    }

    @Test
    void filter_healthPath_bypassesWithoutTenantLookup() {
        // Liveness/readiness probes hit the container IP directly, so the host
        // has no tenant segment. The filter must skip tenant resolution entirely
        // to avoid noisy "Tenant not found" warnings.
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://127.0.0.1:8080/health").build());
        AtomicReference<String> captured = new AtomicReference<>("untouched");
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertNull(captured.get());
    }

    @Test
    void filter_prometheusPath_bypassesWithoutTenantLookup() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("https://127.0.0.1:8080/prometheus").build());
        AtomicReference<String> captured = new AtomicReference<>("untouched");
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, null));
            return Mono.empty();
        });

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

        assertNull(captured.get());
    }
}
