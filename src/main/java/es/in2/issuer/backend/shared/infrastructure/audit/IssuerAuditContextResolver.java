package es.in2.issuer.backend.shared.infrastructure.audit;

import com.eudistack.auditoria.domain.ActorKind;
import com.eudistack.auditoria.domain.AuditActor;
import com.eudistack.auditoria.domain.AuditContext;
import com.eudistack.auditoria.port.ReactiveAuditContextResolver;
import es.in2.issuer.backend.shared.domain.service.AccessTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;

/**
 * Tells the audit starter who is acting in a request: the tenant of the request and the caller of its
 * access token. The wallet's token names the issuance ({@code pid}) and is the holder; a machine token
 * names its client and is a system; any other is a person. A request without an authenticated caller has
 * no context, so the steps of the holder's exchange that carry no token open one explicitly.
 */
@Component
@RequiredArgsConstructor
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
public class IssuerAuditContextResolver implements ReactiveAuditContextResolver {

    private static final String ISSUANCE_CLAIM = "pid";
    private static final String CLIENT_CLAIM = "client_id";
    private static final String EMAIL_CLAIM = "email";
    /** What the authentication manager names a caller whose token carries no mandatee email. */
    private static final String ANONYMOUS_PRINCIPAL = "anonymous";

    private final AccessTokenService accessTokenService;

    @Override
    public Mono<AuditContext> resolve(ServerWebExchange exchange, @Nullable Authentication authentication) {
        return Mono.deferContextual(ctx -> {
            String tenant = ctx.getOrDefault(TENANT_DOMAIN_CONTEXT_KEY, "");
            if (tenant.isBlank() || !(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
                return Mono.empty();
            }
            Jwt token = jwtAuthentication.getToken();
            AuditActor actor = actorOf(token, jwtAuthentication.getName());
            if (actor.kind() == ActorKind.HOLDER) {
                return Mono.just(new AuditContext(tenant, null, null, actor));
            }
            return organizationOf(exchange)
                    .map(organization -> new AuditContext(tenant, organization, null, actor))
                    .defaultIfEmpty(new AuditContext(tenant, null, null, actor));
        });
    }

    private static AuditActor actorOf(Jwt token, String principalName) {
        String issuanceId = token.getClaimAsString(ISSUANCE_CLAIM);
        if (issuanceId != null && !issuanceId.isBlank()) {
            return AuditActor.holder(issuanceId);
        }
        String client = token.getClaimAsString(CLIENT_CLAIM);
        if (client != null && !client.isBlank()) {
            return AuditActor.system(client);
        }
        boolean named = principalName != null && !principalName.isBlank() && !ANONYMOUS_PRINCIPAL.equals(principalName);
        String id = named ? principalName : token.getSubject();
        return AuditActor.person(id, null, token.getClaimAsString(EMAIL_CLAIM));
    }

    /** The organization is optional evidence: a token without one is still a valid caller. */
    private Mono<String> organizationOf(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null) {
            return Mono.empty();
        }
        return accessTokenService.getOrganizationId(authorization).onErrorResume(_ -> Mono.empty());
    }
}
