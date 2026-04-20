package es.in2.issuer.backend.shared.infrastructure.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URI;

import static es.in2.issuer.backend.shared.domain.util.Constants.ISSUER_BASE_URL_CONTEXT_KEY;

/**
 * Builds the public-facing base URL (scheme + host + port + context path) and
 * stores it in the Reactor subscriber context.
 *
 * <p>The context path is read from {@code spring.webflux.base-path}, which is
 * also what Spring WebFlux uses for routing — so public URL construction and
 * request routing share the same source of truth. The env override is
 * {@code APP_CONTEXT_PATH}.
 *
 * <p>Result: {@code https://kpmg.eudistack.net/issuer}
 */
@Component
@Order(3)
public class IssuerBaseUrlWebFilter implements WebFilter {

    private final String configuredContextPath;

    public IssuerBaseUrlWebFilter(@Value("${spring.webflux.base-path:}") String contextPath) {
        this.configuredContextPath = normalizeContextPath(contextPath);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        URI uri = exchange.getRequest().getURI();
        String baseUrl = buildBaseUrl(uri, configuredContextPath);
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(ISSUER_BASE_URL_CONTEXT_KEY, baseUrl));
    }

    private static String normalizeContextPath(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed;
        }
        if (trimmed.length() > 1 && trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return "/".equals(trimmed) ? null : trimmed;
    }

    private static String buildBaseUrl(URI uri, String contextPath) {
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort();
        boolean defaultPort = port == -1
                || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);

        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(host);
        if (!defaultPort) {
            sb.append(":").append(port);
        }
        if (contextPath != null && !contextPath.isBlank()) {
            sb.append(contextPath);
        }
        return sb.toString();
    }
}
