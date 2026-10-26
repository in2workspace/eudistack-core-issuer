package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.infrastructure.config.tenantconfig.TenantCustomDomainsLoader;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.ENVIRONMENT_LABEL_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.HEALTH_PATH;
import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.PROMETHEUS_PATH;

/**
 * Stores the environment label of the request host (e.g. {@code SBX}) in the Reactor context so
 * the credential-offer email can prefix its subject without threading a parameter through the
 * issuance flow. The host is matched exactly against the issuer host of each registry entry
 * ({@link TenantCustomDomainsLoader#findEnvironmentLabelByIssuerHost}). Requests whose host has no label
 * (canonical hosts, production) pass through untouched.
 */
@Component
public class EnvironmentLabelWebFilter implements WebFilter {

    private final TenantCustomDomainsLoader tenantCustomDomainsLoader;

    public EnvironmentLabelWebFilter(TenantCustomDomainsLoader tenantCustomDomainsLoader) {
        this.tenantCustomDomainsLoader = tenantCustomDomainsLoader;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (isTenantAgnostic(path)) {
            return chain.filter(exchange);
        }
        String host = exchange.getRequest().getURI().getHost();
        Optional<String> label = tenantCustomDomainsLoader.findEnvironmentLabelByIssuerHost(host);
        return label
                .map(value -> chain.filter(exchange).contextWrite(ctx -> ctx.put(ENVIRONMENT_LABEL_CONTEXT_KEY, value)))
                .orElseGet(() -> chain.filter(exchange));
    }

    private static boolean isTenantAgnostic(String path) {
        return path.equals(HEALTH_PATH) || path.startsWith(HEALTH_PATH + "/")
                || path.equals(PROMETHEUS_PATH) || path.startsWith(PROMETHEUS_PATH + "/");
    }
}
