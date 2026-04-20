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
 * <p>Context-path resolution order:
 * <ol>
 *     <li>{@code app.context-path} configuration property (env
 *         {@code APP_CONTEXT_PATH}, default {@code /issuer}) — authoritative
 *         when deployed behind CloudFront/ALB, which do not inject
 *         {@code X-Forwarded-Prefix}.</li>
 *     <li>{@code request.getPath().contextPath()} — populated by Spring's
 *         {@code ForwardedHeaderTransformer} from {@code X-Forwarded-Prefix}
 *         (local dev via nginx).</li>
 * </ol>
 *
 * <p>Note: {@code spring.webflux.base-path} is intentionally disabled —
 * it breaks Reactor context propagation to the R2DBC tenant decorator.
 *
 * <p>Result: {@code https://kpmg.eudistack.net/issuer}
 */
@Component
@Order(3)
public class IssuerBaseUrlWebFilter implements WebFilter {

    private final String configuredContextPath;

    public IssuerBaseUrlWebFilter(@Value("${app.context-path:}") String contextPath) {
        this.configuredContextPath = normalizeContextPath(contextPath);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        URI uri = exchange.getRequest().getURI();
        String contextPath = resolveContextPath(exchange);
        String baseUrl = buildBaseUrl(uri, contextPath);
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(ISSUER_BASE_URL_CONTEXT_KEY, baseUrl));
    }

    private String resolveContextPath(ServerWebExchange exchange) {
        if (configuredContextPath != null) {
            return configuredContextPath;
        }
        // Fallback to what ForwardedHeaderTransformer derived from X-Forwarded-Prefix.
        return exchange.getRequest().getPath().contextPath().value();
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
