package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.concurrent.atomic.AtomicReference;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class MdcContextConfigTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void accessor_writesReactorContextKeyToMdcAndCleansUp() {
        new MdcContextConfig().registerTenantDomainAccessor();
        Hooks.enableAutomaticContextPropagation();

        AtomicReference<String> observed = new AtomicReference<>();
        Mono<Void> pipeline = Mono.fromRunnable(() -> observed.set(MDC.get(TENANT_DOMAIN_CONTEXT_KEY)))
                .then()
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, "altia"));

        StepVerifier.create(pipeline).verifyComplete();

        assertEquals("altia", observed.get(), "MDC should carry the tenant while operator runs");
        assertNull(MDC.get(TENANT_DOMAIN_CONTEXT_KEY), "MDC should be cleaned after operator completes");
    }
}
