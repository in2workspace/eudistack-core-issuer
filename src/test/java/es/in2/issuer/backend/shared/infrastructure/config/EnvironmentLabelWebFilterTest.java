package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.tenantconfig.TenantCustomDomainsLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.ENVIRONMENT_LABEL_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class EnvironmentLabelWebFilterTest {

    private TenantCustomDomainsLoader loader;
    private EnvironmentLabelWebFilter filter;

    @BeforeEach
    void setUp() {
        loader = mock(TenantCustomDomainsLoader.class);
        filter = new EnvironmentLabelWebFilter(loader);
    }

    private String labelSeenDownstream(String url) {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(url));
        AtomicReference<String> captured = new AtomicReference<>();
        WebFilterChain chain = ex -> Mono.deferContextual(ctx -> {
            captured.set(ctx.getOrDefault(ENVIRONMENT_LABEL_CONTEXT_KEY, null));
            return Mono.empty();
        });
        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        return captured.get();
    }

    @Test
    void filter_hostWithLabel_putsLabelInReactorContext() {
        when(loader.findEnvironmentLabelByIssuerHost("issuer.dev.dome.example")).thenReturn(Optional.of("Dev"));

        assertEquals("Dev", labelSeenDownstream("https://issuer.dev.dome.example/issuer/ping"));
    }

    @Test
    void filter_hostWithoutLabel_leavesContextUntouched() {
        when(loader.findEnvironmentLabelByIssuerHost("dome.eudistack.net")).thenReturn(Optional.empty());

        assertNull(labelSeenDownstream("https://dome.eudistack.net/issuer/ping"));
    }

    @Test
    void filter_healthPath_skipsLookup() {
        assertNull(labelSeenDownstream("https://issuer.dev.dome.example/health"));

        verifyNoInteractions(loader);
    }
}
