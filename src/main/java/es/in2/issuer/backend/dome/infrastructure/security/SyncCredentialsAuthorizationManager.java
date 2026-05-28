package es.in2.issuer.backend.dome.infrastructure.security;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Arrays;

@Component
public class SyncCredentialsAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
        return authentication
                .map(auth -> {

                    if (!(auth.getPrincipal() instanceof Jwt jwt)) {
                        return new AuthorizationDecision(false);
                    }

                    String tenant = jwt.getClaimAsString("tenant");
                    boolean hasTenant = "dome".equals(tenant);

                    // scope puede venir como string o lista
                    boolean hasPermission = false;

                    Object scopeClaim = jwt.getClaims().get("scope");

                    if (scopeClaim instanceof String scopeString) {

                        hasPermission =
                                java.util.Arrays.stream(scopeString.split(" "))
                                        .anyMatch("DomeRecovery/Sync"::equals);

                    } else if (scopeClaim instanceof java.util.Collection<?> scopes) {

                        hasPermission =
                                scopes.contains("DomeRecovery/Sync");
                    }

                    return new AuthorizationDecision(
                            hasTenant && hasPermission
                    );
                })
                .defaultIfEmpty(new AuthorizationDecision(false));
    }
}

