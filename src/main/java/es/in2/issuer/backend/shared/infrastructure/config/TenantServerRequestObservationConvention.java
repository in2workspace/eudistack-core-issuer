package es.in2.issuer.backend.shared.infrastructure.config;

import io.micrometer.common.KeyValue;
import io.micrometer.common.KeyValues;
import org.springframework.http.server.reactive.observation.DefaultServerRequestObservationConvention;
import org.springframework.http.server.reactive.observation.ServerRequestObservationContext;
import org.springframework.stereotype.Component;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Adds a {@code tenant} low-cardinality tag to the auto-configured
 * {@code http.server.requests} observation, so error-rate and latency can be
 * sliced per tenant. Registering this bean overrides Boot's default convention
 * ({@code @ConditionalOnMissingBean(ServerRequestObservationConvention.class)}).
 *
 * <p>Reads the tenant from the exchange attribute set by
 * {@link TenantDomainWebFilter} rather than the Reactor Context — by the time
 * this convention runs (on observation stop), the Context is no longer accessible.
 */
@Component
public class TenantServerRequestObservationConvention extends DefaultServerRequestObservationConvention {

    private static final String UNKNOWN_TENANT = "unknown";

    @Override
    public KeyValues getLowCardinalityKeyValues(ServerRequestObservationContext context) {
        return super.getLowCardinalityKeyValues(context).and(tenant(context));
    }

    private KeyValue tenant(ServerRequestObservationContext context) {
        Object tenant = context.getAttributes().get(TENANT_DOMAIN_CONTEXT_KEY);
        return KeyValue.of("tenant", tenant instanceof String value && !value.isBlank() ? value : UNKNOWN_TENANT);
    }
}
