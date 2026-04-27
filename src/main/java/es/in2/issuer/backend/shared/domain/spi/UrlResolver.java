package es.in2.issuer.backend.shared.domain.spi;

import org.springframework.web.server.ServerWebExchange;

/**
 * Single source of truth for resolving the issuer's public and internal URLs.
 *
 * <p><b>Public URLs</b> are derived from the live {@link ServerWebExchange}
 * (scheme + host + port + {@code spring.webflux.base-path}), which Spring
 * already populates correctly when running behind a trusted proxy — nginx
 * locally, ALB + CloudFront in STG/PROD — via
 * {@code server.forward-headers-strategy=framework} and {@code X-Forwarded-*}
 * headers. There is no static "APP_URL" config; the URL is always the one
 * the caller actually sees.
 *
 * <p><b>Internal URLs</b> come from {@code APP_INTERNAL_URL} and
 * {@code APP_VERIFIER_INTERNAL_URL}. These point to intra-VPC DNS names
 * (Cloud Map / docker network) and MUST include the service base-path
 * (e.g. {@code http://verifier-core.stg.eudistack.local:8080/verifier}).
 *
 * <p>Implementations MUST NOT expose constants starting with {@code /}
 * concatenated to a URL via {@code +}: a base URL that already carries a
 * base-path would be mangled (see EUDI-017 post-cutover for the historical
 * bug). Use {@link org.springframework.web.util.UriComponentsBuilder} or
 * the helpers in this port.
 */
public interface UrlResolver {

    /**
     * Public base URL of this issuer backend as seen by the caller
     * (scheme + host + port + context-path). Example:
     * {@code https://sandbox-stg.eudistack.net/issuer}.
     */
    String publicIssuerBaseUrl(ServerWebExchange exchange);

    /**
     * Public origin of the current request (scheme + host + port, no path).
     * Example: {@code https://sandbox-stg.eudistack.net}.
     */
    String publicOrigin(ServerWebExchange exchange);

    /**
     * Base URL at which the verifier is expected to serve tokens reaching
     * this issuer under same-origin (Atlassian-style) routing:
     * {@code ${publicOrigin}/verifier}. Used by the authentication layer
     * to validate the {@code iss} claim of verifier-emitted tokens by
     * exact match, with no dependency on {@code APP_VERIFIER_URL}.
     */
    String expectedVerifierBaseUrl(ServerWebExchange exchange);

    /**
     * Intra-VPC base URL of the verifier, including its base-path.
     * Example: {@code http://verifier-core.stg.eudistack.local:8080/verifier}.
     */
    String internalVerifierBaseUrl();

    /**
     * Intra-VPC base URL of this issuer backend, including its base-path.
     * Example: {@code http://issuer-core.stg.eudistack.local:8080/issuer}.
     */
    String internalIssuerBaseUrl();

    /**
     * Rewrites an absolute public URL to point to the internal verifier
     * origin, preserving the URL's path component as-is.
     *
     * <p>The public URL path typically already carries the verifier
     * base-path (e.g. {@code /verifier/oauth2/jwks}); therefore the
     * rewrite replaces <em>only</em> the origin and does NOT prepend the
     * internal base-path a second time.
     *
     * @param publicAbsoluteUrl absolute URL returned by the verifier's
     *                          well-known document (e.g. {@code jwks_uri})
     * @return the same path served from the internal verifier origin
     */
    String rewriteToInternalVerifier(String publicAbsoluteUrl);
}
