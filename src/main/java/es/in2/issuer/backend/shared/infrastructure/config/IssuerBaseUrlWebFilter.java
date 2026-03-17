package es.in2.issuer.backend.shared.infrastructure.config;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;

/**
 * Extracts the public-facing base URL (scheme + host + port) from the incoming
 * request — after Spring's {@code ForwardedHeaderTransformer} has processed
 * {@code X-Forwarded-Host} / {@code X-Forwarded-Proto} headers — and stores it
 * in the Reactor subscriber context.
 *
 * <p>Downstream services read this value with
 * {@code Mono.deferContextual(ctx -> ctx.getOrDefault(ISSUER_BASE_URL_CONTEXT_KEY, fallback))}
 * to generate correct per-tenant URLs in OID4VCI discovery, credential offers,
 * and token claims.
 *
 * <p>When no forwarded headers are present (e.g., direct backend access or
 * scheduler context), the context key is absent and services fall back to the
 * static {@code APP_URL} configuration.
 */
@Component
@Order(3)
public class IssuerBaseUrlWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        URI uri = exchange.getRequest().getURI();
        String baseUrl = buildBaseUrl(uri);
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(ISSUER_BASE_URL_CONTEXT_KEY, baseUrl));
    }

    private static String buildBaseUrl(URI uri) {
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort();
        boolean defaultPort = port == -1
                || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
        if (defaultPort) {
            return scheme + "://" + host;
        }
        return scheme + "://" + host + ":" + port;
    }
}
