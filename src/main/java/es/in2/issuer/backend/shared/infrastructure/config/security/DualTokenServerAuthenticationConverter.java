package es.in2.issuer.backend.shared.infrastructure.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
public final class DualTokenServerAuthenticationConverter implements ServerAuthenticationConverter {

    private static final String ID_TOKEN_HEADER = "X-ID-Token";

    @Override
    public Mono<org.springframework.security.core.Authentication> convert(ServerWebExchange exchange) {
        var request = exchange.getRequest();
        var path = request.getPath();
        var method = request.getMethod();
        log.debug("DualTokenServerAuthenticationConverter - convert -> [{} {}]",
                method,
                path);

        String auth = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (auth == null) {
            return Mono.empty();
        }
        String accessToken;
        if (auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            accessToken = auth.substring(7).trim();
        } else if (auth.regionMatches(true, 0, "DPoP ", 0, 5)) {
            accessToken = auth.substring(5).trim();
        } else {
            return Mono.empty();
        }
        String idToken = request.getHeaders().getFirst(ID_TOKEN_HEADER);
        return Mono.just(new es.in2.issuer.backend.shared.infrastructure.config.security.DualTokenAuthentication(accessToken, (idToken == null || idToken.isBlank()) ? null : idToken));
    }
}

