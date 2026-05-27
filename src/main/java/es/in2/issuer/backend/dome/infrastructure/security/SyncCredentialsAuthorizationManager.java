package es.in2.issuer.backend.dome.infrastructure.security;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import org.springframework.security.oauth2.jwt.Jwt;

@Component
public class SyncCredentialsAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
        return authentication
                .map(auth -> {
                    // Comprobamos si el token es un JWT
                    if (auth.getPrincipal() instanceof Jwt jwt) {
                        // Extraemos el claim "tenant"
                        String tenant = jwt.getClaimAsString("tenant");
                        boolean hasTenant = "dome".equals(tenant);

                        // Extraemos la lista de scopes/permisos
                        var scopes = jwt.getClaimAsStringList("scope");
                        boolean hasPermission = scopes != null && scopes.contains("DomeRecovery/Sync");

                        return new AuthorizationDecision(hasTenant && hasPermission);
                    }
                    return new AuthorizationDecision(false);
                })
                .defaultIfEmpty(new AuthorizationDecision(false)); // Si no hay token, denegado
    }
}

