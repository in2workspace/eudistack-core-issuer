package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.util.GlobalErrorTypes;
import es.in2.issuer.backend.shared.domain.util.LogSafe;
import es.in2.issuer.backend.shared.domain.util.Sha256;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static es.in2.issuer.backend.shared.infrastructure.config.ApiOperationResolver.MANAGEMENT_API_PREFIX;

/**
 * SEC-06: Simple per-IP rate limiter for mutating endpoints.
 * Uses a sliding window (1 minute) with a configurable max requests per IP.
 * Rejects excess requests with HTTP 429 Too Many Requests, as an {@code application/problem+json}
 * {@code rate_limited} with {@code Retry-After} on every route (EUD-295: the issuance API contract
 * fixes that body, the same one {@link ApiVolumeLimitFilter} writes for the limit of the requester).
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RateLimitFilter implements WebFilter {

    static final int RETRY_AFTER_SECONDS = 60;
    private static final byte[] RATE_LIMITED_PROBLEM = ("{\"type\":\"" + GlobalErrorTypes.RATE_LIMITED.getCode()
            + "\",\"title\":\"Too many requests\",\"status\":429,"
            + "\"detail\":\"The volume limit was exceeded. Retry after the time in Retry-After.\"}")
            .getBytes(StandardCharsets.UTF_8);

    /** How long a credential that was counted by its requester is let through an address over its limit. */
    static final Duration COUNTED_CREDENTIAL_TTL = Duration.ofMinutes(10);

    private final int maxRequestsPerMinute;
    private final Cache<String, AtomicInteger> requestCounts;
    private final Cache<String, AtomicInteger> uncountedRequests;
    /**
     * Digests of the {@code Authorization} header, the {@code X-Tenant} and the operation of the requests that were
     * counted in the limit of their requester recently on this instance.
     */
    private final Cache<String, Boolean> countedCredentials;

    public RateLimitFilter(
            @Value("${issuer.api.rate-limit.max-per-minute:100}") int maxRequestsPerMinute) {
        this.maxRequestsPerMinute = maxRequestsPerMinute;
        this.requestCounts = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(50_000)
                .build();
        this.uncountedRequests = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(50_000)
                .build();
        this.countedCredentials = Caffeine.newBuilder()
                .expireAfterWrite(COUNTED_CREDENTIAL_TTL)
                .maximumSize(50_000)
                .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpMethod method = exchange.getRequest().getMethod();
        if (method == null || method == HttpMethod.GET || method == HttpMethod.OPTIONS || method == HttpMethod.HEAD) {
            return chain.filter(exchange);
        }
        if (hasVolumeLimitOfItsRequester(exchange)) {
            return limitUncountedRequests(exchange, chain);
        }

        String clientIp = resolveClientIp(exchange);
        AtomicInteger counter = requestCounts.get(clientIp, k -> new AtomicInteger(0));
        int current = counter.incrementAndGet();

        if (current > maxRequestsPerMinute) {
            log.warn("Rate limit exceeded for IP {}: {}/{} requests/min on {} {}",
                    clientIp, current, maxRequestsPerMinute,
                    method, exchange.getRequest().getPath().value());
            return reject(exchange);
        }

        return chain.filter(exchange);
    }

    /**
     * On the issuance, revocation and query APIs a request counted in the volume limit of its requester (EUD-269,
     * {@link ApiVolumeLimitFilter#COUNTED_ATTRIBUTE}) is not counted per address. Every other request of those
     * routes is, whatever its status: one without a verified token (a 401, but also a 5xx when the token could not
     * be checked, which costs a call to the verifier), and one with a valid token that has no requester (another
     * tenant in {@code X-Tenant}, a token that names no organization) or whose route has no operation. An address
     * over the limit is rejected before its token is verified, so no request of these routes goes without a limit.
     *
     * <p>The address is the first {@code X-Forwarded-For} value, which a client can set, so a flood of invalid
     * tokens can name another client's address. That client is not locked out with a credential already counted by
     * its requester on this instance, for the same tenant and operation: it goes through. Only its first request
     * with a new credential during such a flood is rejected (residual risk, until the address is taken only from
     * the trusted proxies).
     */
    private Mono<Void> limitUncountedRequests(ServerWebExchange exchange, WebFilterChain chain) {
        String clientIp = resolveClientIp(exchange);
        String credential = countableCredential(exchange);
        AtomicInteger uncounted = uncountedRequests.getIfPresent(clientIp);
        if (uncounted != null && uncounted.get() >= maxRequestsPerMinute
                && (credential == null || countedCredentials.getIfPresent(credential) == null)) {
            log.warn("Rate limit of uncounted requests exceeded for IP {} on {} {}", LogSafe.of(clientIp),
                    exchange.getRequest().getMethod(), exchange.getRequest().getPath().value());
            return reject(exchange);
        }
        return chain.filter(exchange).doFinally(signal -> {
            if (Boolean.TRUE.equals(exchange.getAttribute(ApiVolumeLimitFilter.COUNTED_ATTRIBUTE))) {
                if (credential != null) {
                    countedCredentials.put(credential, Boolean.TRUE);
                }
            } else {
                uncountedRequests.get(clientIp, k -> new AtomicInteger(0)).incrementAndGet();
            }
        });
    }

    /**
     * Digest of what decides whether a request is counted by its requester -- the {@code Authorization} header,
     * the {@code X-Tenant} and the operation -- never kept in clear: a credential counted for one tenant or
     * operation is not let through for another, where it may have no requester. {@code null} without a credential
     * or an operation, which are never counted by their requester.
     */
    private static String countableCredential(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null || authorization.isBlank()) {
            return null;
        }
        return ApiOperationResolver.resolve(exchange.getRequest().getMethod(),
                        exchange.getRequest().getPath().pathWithinApplication().value())
                .map(operation -> {
                    String tenant = exchange.getRequest().getHeaders().getFirst(X_TENANT_HEADER);
                    return Sha256.hex(authorization + "\n"
                            + (tenant == null ? "" : tenant.trim().toLowerCase(Locale.ROOT)) + "\n"
                            + operation.key());
                })
                .orElse(null);
    }

    private static Mono<Void> reject(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        response.getHeaders().set(HttpHeaders.RETRY_AFTER, String.valueOf(RETRY_AFTER_SECONDS));
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        // Written before Spring Security's header writer runs, so the 429 sets its own (§8.1).
        response.getHeaders().set("X-Content-Type-Options", "nosniff");
        response.getHeaders().setCacheControl("no-store");
        return response.writeWith(Mono.just(response.bufferFactory().wrap(RATE_LIMITED_PROBLEM)));
    }

    /**
     * The issuance, revocation and query APIs have the volume limit of their requester -- per person, and per
     * organization for its systems, shared by every instance -- instead of this one per address (EUD-269,
     * {@link ApiVolumeLimitFilter}): here only the requests it did not count. Every other route keeps it whole,
     * among them the public OID4VCI ones.
     */
    private static boolean hasVolumeLimitOfItsRequester(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        return path.equals(MANAGEMENT_API_PREFIX) || path.startsWith(MANAGEMENT_API_PREFIX + "/");
    }

    private String resolveClientIp(ServerWebExchange exchange) {
        // Prefer X-Forwarded-For header (set by nginx) when available.
        // When FORWARD_HEADERS_STRATEGY=FRAMEWORK is active, Spring consumes this header
        // and rewrites remoteAddress, so the header won't be present and we fall through
        // to remoteAddress below. When the strategy is not active, the header is still
        // present and we use it directly.
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        InetSocketAddress remoteAddress = exchange.getRequest().getRemoteAddress();
        if (remoteAddress == null) {
            return "unknown";
        }
        // getAddress() can be null when ForwardedHeaderTransformer creates an unresolved InetSocketAddress
        return remoteAddress.getAddress() != null
                ? remoteAddress.getAddress().getHostAddress()
                : remoteAddress.getHostString();
    }
}