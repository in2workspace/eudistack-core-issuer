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
 * Builds the public-facing base URL (scheme + host + port + path prefix) and
 * stores it in the Reactor subscriber context.
 *
 * <p>After Spring's {@code ForwardedHeaderTransformer} processes X-Forwarded-Host
 * and X-Forwarded-Proto, the request URI reflects the public hostname. This filter
 * also reads {@code X-Forwarded-Prefix} (set by nginx/ALB) to include the path
 * prefix (e.g., {@code /issuer}) in the base URL.
 *
 * <p>Result: {@code https://kpmg.eudistack.net/issuer}
 */
@Component
@Order(3)
public class IssuerBaseUrlWebFilter implements WebFilter {

    private static final String FORWARDED_PREFIX_HEADER = "X-Forwarded-Prefix";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        URI uri = exchange.getRequest().getURI();
        String prefix = exchange.getRequest().getHeaders().getFirst(FORWARDED_PREFIX_HEADER);
        String baseUrl = buildBaseUrl(uri, prefix);
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(ISSUER_BASE_URL_CONTEXT_KEY, baseUrl));
    }

    private static String buildBaseUrl(URI uri, String prefix) {
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
        if (prefix != null && !prefix.isBlank()) {
            sb.append(prefix);
        }
        return sb.toString();
    }
}
