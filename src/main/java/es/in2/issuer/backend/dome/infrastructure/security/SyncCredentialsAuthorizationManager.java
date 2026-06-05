package es.in2.issuer.backend.dome.infrastructure.security;

import es.in2.issuer.backend.shared.domain.util.Constants;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Security Authorization Manger that enforces PBAC (Policy Based Access Control)
 * for the credential synchronization endpoint.
 * Ensures the request comes from the correct tenant and possesses the required recovery scope.
 */
@Component
public class SyncCredentialsAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
        return authentication
                .map(auth -> {

                    // Step 1: Ensure the principal is actually a JSON Web Token
                    if (!(auth.getPrincipal() instanceof Jwt jwt)) {
                        return new AuthorizationDecision(false);
                    }

                    // Step 2: Validate the tenant claim
                    String tenant = jwt.getClaimAsString(Constants.JWT_CLAIM_TENANT);
                    boolean hasTenant = Constants.TENANT_DOME.equals(tenant);

                    // Step 3: Validate the required scope
                    boolean hasPermission = false;
                    Object scopeClaim = jwt.getClaims().get(Constants.JWT_CLAIM_SCOPE);

                    if (scopeClaim instanceof String scopeString) {

                        hasPermission =
                                java.util.Arrays.stream(scopeString.split(" "))
                                        .anyMatch(Constants.SCOPE_DOME_RECOVERY_SYNC::equals);

                    } else if (scopeClaim instanceof java.util.Collection<?> scopes) {

                        hasPermission =
                                scopes.contains(Constants.SCOPE_DOME_RECOVERY_SYNC);
                    }

                    // Final decision: must belong to the DOME tenant and have the specific sync scope
                    return new AuthorizationDecision(
                            hasTenant && hasPermission
                    );
                })
                .defaultIfEmpty(new AuthorizationDecision(false));
    }
}

