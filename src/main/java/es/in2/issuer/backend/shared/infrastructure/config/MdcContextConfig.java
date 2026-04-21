package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.context.ContextRegistry;
import io.micrometer.context.ThreadLocalAccessor;
import jakarta.annotation.PostConstruct;
import org.slf4j.MDC;
import org.springframework.context.annotation.Configuration;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Registers a {@link ThreadLocalAccessor} that bridges the Reactor subscriber
 * context key {@code tenantDomain} with SLF4J {@link MDC}.
 *
 * <p>Combined with {@code Hooks.enableAutomaticContextPropagation()} (enabled
 * in {@code IssuerApiApplication.main}) and
 * {@code spring.reactor.context-propagation: auto}, this makes the MDC value
 * visible to logback patterns such as {@code %X{tenantDomain:-}} on every
 * operator execution across threads.
 *
 * <p>The accessor key MUST match the Reactor context key and the MDC key
 * ({@code tenantDomain}) for automatic bridging to work.
 */
@Configuration(proxyBeanMethods = false)
public class MdcContextConfig {

    @PostConstruct
    public void registerTenantDomainAccessor() {
        ContextRegistry.getInstance().registerThreadLocalAccessor(
                new MdcThreadLocalAccessor(TENANT_DOMAIN_CONTEXT_KEY));
    }

    /**
     * Reads/writes a single MDC key as if it were a {@link ThreadLocal}.
     * The accessor key equals the MDC key so that
     * {@code ContextRegistry} bridges {@code ctx.get(key)} to {@code MDC.put(key, value)}.
     */
    static final class MdcThreadLocalAccessor implements ThreadLocalAccessor<String> {

        private final String key;

        MdcThreadLocalAccessor(String key) {
            this.key = key;
        }

        @Override
        public Object key() {
            return key;
        }

        @Override
        public String getValue() {
            return MDC.get(key);
        }

        @Override
        public void setValue(String value) {
            MDC.put(key, value);
        }

        @Override
        public void setValue() {
            MDC.remove(key);
        }
    }
}
