package es.in2.issuer.backend.shared.infrastructure.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import es.in2.issuer.backend.shared.domain.util.LogSafe;
import es.in2.issuer.backend.shared.domain.util.Sha256;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static es.in2.issuer.backend.shared.infrastructure.config.ApiOperationResolver.MANAGEMENT_API_PREFIX;

/**
 * SEC-06: Simple per-IP rate limiter for mutating endpoints.
 * Uses a sliding window (1 minute) with a configurable max requests per IP.
 * Rejects excess requests with HTTP 429 Too Many Requests.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RateLimitFilter implements WebFilter {

    /**
     * Exchange attribute the security layer sets when it verifies the request's credential (see
     * {@code SecurityConfig}): a request that ends without it was not authenticated, whatever its status.
     */
    public static final String AUTHENTICATED_ATTRIBUTE = RateLimitFilter.class.getName() + ".authenticated";

    /** How long a credential that authenticated is let through an address over its limit of failures. */
    static final Duration AUTHENTICATED_CREDENTIAL_TTL = Duration.ofMinutes(10);

    private final int maxRequestsPerMinute;
    private final Cache<String, AtomicInteger> requestCounts;
    private final Cache<String, AtomicInteger> failedAuthentications;
    /** Digests of the {@code Authorization} headers that authenticated recently on this instance. */
    private final Cache<String, Boolean> authenticatedCredentials;

    public RateLimitFilter(
            @Value("${issuer.api.rate-limit.max-per-minute:100}") int maxRequestsPerMinute) {
        this.maxRequestsPerMinute = maxRequestsPerMinute;
        this.requestCounts = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(50_000)
                .build();
        this.failedAuthentications = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(50_000)
                .build();
        this.authenticatedCredentials = Caffeine.newBuilder()
                .expireAfterWrite(AUTHENTICATED_CREDENTIAL_TTL)
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
            return limitFailedAuthentications(exchange, chain);
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
     * On the issuance, revocation and query APIs an authenticated request has the volume limit of its
     * requester instead (EUD-269), so here only the requests that end without a verified credential are counted
     * per address -- whatever their status: a 401, but also a 5xx when the token could not be checked, which
     * costs a call to the verifier. An address over the limit of them is rejected before its token is verified,
     * which keeps floods of invalid or expired tokens throttled.
     *
     * <p>The address is the first {@code X-Forwarded-For} value (TDG-15), which a client can set, so a flood of
     * invalid tokens can name another client's address. That client is not locked out with a credential that
     * already authenticated on this instance: it goes through, and is not counted here. Only its first request
     * with a new credential during such a flood is rejected -- the residual risk noted with TDG-15.
     */
    private Mono<Void> limitFailedAuthentications(ServerWebExchange exchange, WebFilterChain chain) {
        String clientIp = resolveClientIp(exchange);
        String credential = credentialDigest(exchange);
        AtomicInteger failures = failedAuthentications.getIfPresent(clientIp);
        if (failures != null && failures.get() >= maxRequestsPerMinute
                && (credential == null || authenticatedCredentials.getIfPresent(credential) == null)) {
            log.warn("Rate limit of failed authentications exceeded for IP {} on {} {}", LogSafe.of(clientIp),
                    exchange.getRequest().getMethod(), exchange.getRequest().getPath().value());
            return reject(exchange);
        }
        return chain.filter(exchange).doFinally(signal -> {
            if (Boolean.TRUE.equals(exchange.getAttribute(AUTHENTICATED_ATTRIBUTE))) {
                if (credential != null) {
                    authenticatedCredentials.put(credential, Boolean.TRUE);
                }
            } else {
                failedAuthentications.get(clientIp, k -> new AtomicInteger(0)).incrementAndGet();
            }
        });
    }

    /** Digest of the {@code Authorization} header, never kept in clear; {@code null} without one. */
    private static String credentialDigest(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        return authorization == null || authorization.isBlank() ? null : Sha256.hex(authorization);
    }

    private static Mono<Void> reject(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        exchange.getResponse().getHeaders().set("Retry-After", "60");
        return exchange.getResponse().setComplete();
    }

    /**
     * The issuance, revocation and query APIs have the volume limit of their requester -- per person, and per
     * organization for its systems, shared by every instance -- instead of this one per address (EUD-269,
     * {@link ApiVolumeLimitFilter}). Every other route keeps it, among them the public OID4VCI ones.
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