package es.in2.issuer.backend.apiclient.infrastructure.security;

import es.in2.issuer.backend.shared.domain.service.AuditService;
import es.in2.issuer.backend.shared.infrastructure.config.security.ProblemAccessDeniedHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.EndpointsConstants.INTAKE_BASE_PATH;

/**
 * Post-authorization gate for the unattended intake (EUD-75, US-02). Wired
 * manually into {@code SecurityConfig} with
 * {@code addFilterAfter(..., SecurityWebFiltersOrder.AUTHORIZATION)} — NOT a
 * Spring-managed {@code @Component} — for two reasons: (1) it must run after
 * Spring's own {@code .anyExchange().authenticated()} check has already
 * rejected unauthenticated requests with 401, so this filter never has to
 * handle a missing/failed authentication itself; (2) a {@code @Component}
 * implementing {@code WebFilter} gets auto-registered by Spring Boot into
 * every {@code @WebFluxTest} slice across the app (WebFilter beans are
 * globally scanned), which would break unrelated controller slice tests
 * that don't provide {@code ProblemAccessDeniedHandler}/{@code AuditService}.
 *
 * <p>Only decides M2M authorization from claims already present on the
 * token — deliberately does NOT re-resolve the {@code ApiClient} from the
 * database: {@code caller_type} and {@code can_trigger_issuance} are
 * embedded in the token at issuance time (see
 * {@code TokenServiceImpl.buildM2mTokenResponse}), so this gate stays a pure
 * claims check to keep the p95 overhead budget (NFR-S-EUD75-01).
 */
@RequiredArgsConstructor
public class IntakeCallerAuthorizationFilter implements WebFilter {

    private static final String CALLER_TYPE_CLAIM = "caller_type";
    private static final String CAN_TRIGGER_ISSUANCE_CLAIM = "can_trigger_issuance";
    private static final String CLIENT_ID_CLAIM = "client_id";
    private static final String M2M_CALLER_TYPE = "M2M";
    private static final String AUDIT_SUCCESS_EVENT = "intake.auth.success";
    private static final String AUDIT_FAILURE_EVENT = "intake.auth.failure";

    private final ProblemAccessDeniedHandler problemAccessDeniedHandler;
    private final AuditService auditService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        if (!exchange.getRequest().getPath().pathWithinApplication().value().startsWith(INTAKE_BASE_PATH)) {
            return chain.filter(exchange);
        }
        // Mono<Void> never emits a value, so switchIfEmpty on the final Void
        // chain fires on every successful completion too (not just an empty
        // context) — wrapping in Optional keeps "context present vs. absent"
        // a real value the flatMap can branch on exactly once.
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(maybeAuthentication -> maybeAuthentication
                        .map(authentication -> authorize(exchange, chain, authentication))
                        // Defensive fail-closed fallback: this filter runs after
                        // SecurityWebFiltersOrder.AUTHORIZATION, so Spring's own
                        // .anyExchange().authenticated() check has already rejected
                        // unauthenticated requests with 401 — an empty context here
                        // should never happen.
                        .orElseGet(() -> deny(exchange, null, "missing_authentication")));
    }

    private Mono<Void> authorize(ServerWebExchange exchange, WebFilterChain chain, Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof Jwt jwt)) {
            return deny(exchange, null, "not_m2m");
        }
        String clientId = jwt.getClaimAsString(CLIENT_ID_CLAIM);
        if (!M2M_CALLER_TYPE.equals(jwt.getClaimAsString(CALLER_TYPE_CLAIM))) {
            return deny(exchange, clientId, "not_m2m");
        }
        if (!Boolean.TRUE.equals(jwt.getClaimAsBoolean(CAN_TRIGGER_ISSUANCE_CLAIM))) {
            return deny(exchange, clientId, "insufficient_scope");
        }
        auditService.auditSuccess(AUDIT_SUCCESS_EVENT, clientId, "intake", null, Map.of());
        return chain.filter(exchange);
    }

    private Mono<Void> deny(ServerWebExchange exchange, String clientId, String cause) {
        auditService.auditFailure(AUDIT_FAILURE_EVENT, clientId, cause, Map.of());
        return problemAccessDeniedHandler.handle(exchange, new AccessDeniedException(cause));
    }
}
