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
 * Builds the public-facing base URL (scheme + host + port + context path) and
 * stores it in the Reactor subscriber context.
 *
 * <p>After Spring's {@code ForwardedHeaderTransformer} processes X-Forwarded-Host,
 * X-Forwarded-Proto, and X-Forwarded-Prefix, the request URI and context path
 * reflect the public hostname and path prefix. This filter reads those resolved
 * values (not the raw headers, which are already stripped).
 *
 * <p>Result: {@code https://kpmg.eudistack.net/issuer}
 */
@Component
@Order(3)
public class IssuerBaseUrlWebFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        URI uri = exchange.getRequest().getURI();
        // ForwardedHeaderTransformer already set contextPath from X-Forwarded-Prefix
        String contextPath = exchange.getRequest().getPath().contextPath().value();
        String baseUrl = buildBaseUrl(uri, contextPath);
        return chain.filter(exchange)
                .contextWrite(ctx -> ctx.put(ISSUER_BASE_URL_CONTEXT_KEY, baseUrl));
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
