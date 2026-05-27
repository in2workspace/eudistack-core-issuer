package es.in2.issuer.backend.dome.infrastructure.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Base64;

/**
 * Filtro de seguridad para validar ataques de repetición (Replay Attacks)
 * leyendo la cabecera DPoP y cacheando su identificador único (JTI).
 */
@Component
public class DpopValidationFilter implements WebFilter {

    private final Cache<String, String> jtiCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10))
            .maximumSize(100_000)
            .build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        if (!path.contains("/internal/dome/sync-credentials")) {
            return chain.filter(exchange);
        }

        String dpopHeader = exchange.getRequest().getHeaders().getFirst("DPoP");

        if (dpopHeader != null && !dpopHeader.isBlank()) {
            try {
                String[] parts = dpopHeader.split("\\.");
                if (parts.length == 3) {
                    String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
                    JsonNode payload = objectMapper.readTree(payloadJson);

                    if (payload.has("jti")) {
                        String jti = payload.get("jti").asText();

                        if (jtiCache.getIfPresent(jti) != null) {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        }
                        jtiCache.put(jti, "used");
                    }
                }
            } catch (Exception e) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }
        return chain.filter(exchange);
    }
}