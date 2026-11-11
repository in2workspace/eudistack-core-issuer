package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.model.requestcontrol.ApiOperation;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.Requester;
import es.in2.issuer.backend.shared.domain.model.requestcontrol.VolumeLimitDecision;
import es.in2.issuer.backend.shared.domain.service.VolumeLimitService;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.domain.util.LogSafe;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Locale;
import java.util.Optional;

/**
 * Volume limits of the issuance, revocation and query APIs (EUD-269): per person, and per organization
 * for its systems, counted in a store shared by every instance. Over the limit, the request is answered
 * 429 {@code rate_limited} in {@code application/problem+json} with {@code Retry-After}, before anything
 * else is decided.
 *
 * <p>Runs after authentication, since the limit depends on who sends the request, and after
 * {@link TenantDomainWebFilter}, since the counters live in the tenant's schema. A request that names no
 * organization is not counted: it is rejected downstream on its own merits. If the counters cannot be
 * read, the request goes on (fail open) and the failure is logged: the limit protects the API, it must not
 * take it down.
 *
 * <p>Registered as a bean in {@link ApiRequestControlConfig}, not as a {@code @Component}, so the
 * {@code @WebFluxTest} slices of the controllers do not load it.
 */
@Slf4j
public class ApiVolumeLimitFilter implements WebFilter, Ordered {

    /** After {@link TenantDomainWebFilter}, before {@link IdempotencyFilter}: a replay is counted too. */
    public static final int ORDER = TenantDomainWebFilter.ORDER + 10;

    private final RequesterResolver requesterResolver;
    private final VolumeLimitService volumeLimitService;
    private final FilterProblemWriter problemWriter;
    private final IssuanceMetrics metrics;

    public ApiVolumeLimitFilter(RequesterResolver requesterResolver, VolumeLimitService volumeLimitService,
                                FilterProblemWriter problemWriter, IssuanceMetrics metrics) {
        this.requesterResolver = requesterResolver;
        this.volumeLimitService = volumeLimitService;
        this.problemWriter = problemWriter;
        this.metrics = metrics;
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    private record Outcome(Requester requester, VolumeLimitDecision decision) { }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        Optional<ApiOperation> operation = ApiOperationResolver.resolve(exchange.getRequest().getMethod(),
                exchange.getRequest().getPath().pathWithinApplication().value());
        if (operation.isEmpty()) {
            return chain.filter(exchange);
        }
        return requesterResolver.current()
                .flatMap(requester -> volumeLimitService.check(operation.get(), requester)
                        .map(decision -> new Outcome(requester, decision)))
                .onErrorResume(e -> {
                    log.warn("Volume limit not applied to {}: the counters are unavailable: {}",
                            operation.get().key(), e.toString());
                    return Mono.empty();
                })
                .map(outcome -> outcome.decision().allowed() ? Optional.<Outcome>empty() : Optional.of(outcome))
                .defaultIfEmpty(Optional.empty())
                .flatMap(rejected -> rejected.isPresent()
                        ? reject(exchange, operation.get(), rejected.get())
                        : chain.filter(exchange));
    }

    private Mono<Void> reject(ServerWebExchange exchange, ApiOperation operation, Outcome outcome) {
        Requester requester = outcome.requester();
        VolumeLimitDecision decision = outcome.decision();
        // The organization is not personal data; the person is never logged.
        log.warn("Volume limit exceeded: operation={} requester={} organization={} limit={} retryAfter={}s",
                operation.key(), requester.kind(), LogSafe.of(requester.organizationIdentifier()),
                decision.limit(), decision.retryAfterSeconds());
        metrics.recordVolumeLimitRejection(operation.key(), requester.kind().name().toLowerCase(Locale.ROOT));
        return problemWriter.write(exchange, HttpStatus.TOO_MANY_REQUESTS,
                GlobalErrorTypes.RATE_LIMITED.getCode(), "Too many requests",
                "The volume limit was exceeded. Retry after the time in Retry-After.",
                decision.retryAfterSeconds());
    }
}
