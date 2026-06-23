package es.in2.issuer.backend.shared.domain.spi;

import org.springframework.web.server.ServerWebExchange;

import java.util.List;

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
     * Public base URL of this issuer backend as seen by the caller.
     *
     * <ul>
     *   <li><b>Canonical topology</b> (subdomain per tenant, nginx): returns
     *       {@code scheme + host + port + context-path}, e.g.
     *       {@code https://sandbox-stg.eudistack.net/issuer}.</li>
     *   <li><b>Non-canonical topology</b> (CloudFront, context-path absent from
     *       the external URL): returns {@code scheme + host + port} only.
     *       Detected by the presence of a non-blank {@code X-Tenant} header,
     *       which CloudFront always injects in this deployment mode.</li>
     * </ul>
     */
    String publicIssuerBaseUrl(ServerWebExchange exchange);

    /**
     * Public base URL of the wallet PWA as seen by the caller. Used as the
     * base of the wallet deep-link embedded in credential-offer emails.
     *
     * <ul>
     *   <li><b>Non-canonical topology</b> (custom domains): the wallet runs on a
     *       separate host that cannot be derived from the issuer request origin
     *       (e.g. issuer at {@code issuer.dome-marketplace.org}, wallet at
     *       {@code wallet.dome-marketplace.org}). The URL is read from the
     *       tenant custom domains registry ({@code tenants-custom-domains.yaml},
     *       field {@code wallet}), matched by the <em>request host</em>. The host
     *       — not the {@code X-Tenant} header — is the discriminator, because a
     *       tenant may be reached through several domains (canonical and custom)
     *       and {@code X-Tenant} carries the same tenant id for all of them.</li>
     *   <li><b>Canonical topology</b> (subdomain per tenant, path-based per
     *       EUDI-064): issuer and wallet share the same origin and the host is
     *       absent from the registry, so the value falls back to the request
     *       origin plus the wallet context-path — e.g.
     *       {@code https://dome.stg.eudistack.net/wallet}.</li>
     * </ul>
     */
    String publicWalletBaseUrl(ServerWebExchange exchange);

    /**
     * Public origin of the current request (scheme + host + port, no path).
     * Example: {@code https://sandbox-stg.eudistack.net}.
     */
    String publicOrigin(ServerWebExchange exchange);

    /**
     * All base URLs at which a verifier is expected to serve tokens reaching this issuer.
     * Used by the authentication layer to validate the {@code iss} claim of
     * verifier-emitted tokens by exact match against any element of the list.
     *
     * <ul>
     *   <li><b>Canonical topology</b>: single-element list derived from
     *       {@code publicOrigin + verifierContextPath},
     *       e.g. {@code [https://sandbox-stg.eudistack.net/verifier]}.</li>
     *   <li><b>Non-canonical topology</b> (CloudFront, {@code X-Tenant} header present):
     *       list read from the tenant custom domains registry
     *       ({@code tenants-custom-domains.yaml}, field {@code verifiers}).
     *       The verifier is a separate service whose URL cannot be derived
     *       from the issuer request origin in this topology.</li>
     * </ul>
     */
    List<String> expectedVerifierBaseUrls(ServerWebExchange exchange);

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
