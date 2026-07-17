package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.shared.domain.spi.UrlResolver;
import es.in2.issuer.backend.shared.infrastructure.config.tenantconfig.TenantCustomDomainsLoader;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;


/**
 * Implementation of {@link UrlResolver}.
 *
 * <p>Public URLs come from {@link ServerWebExchange#getRequest()} (already
 * rewritten by Spring's {@code ForwardedHeaderTransformer} when
 * {@code server.forward-headers-strategy=framework}). Internal URLs come
 * from the {@code APP_INTERNAL_URL} / {@code APP_VERIFIER_INTERNAL_URL}
 * environment variables and MUST include the service base-path (see the
 * Javadoc on {@link UrlResolver}).
 */
@Component
@Slf4j
public class UrlResolverImpl implements UrlResolver {

    private final String issuerContextPath;
    private final String verifierContextPath;
    private final String walletContextPath;
    private final String issuerInternalUrl;
    private final String verifierInternalUrl;
    private final TenantCustomDomainsLoader tenantCustomDomainsLoader;

    public UrlResolverImpl(
            @Value("${spring.webflux.base-path:}") String issuerContextPath,
            @Value("${app.verifier-base-path:/verifier}") String verifierContextPath,
            @Value("${app.wallet-base-path:/wallet}") String walletContextPath,
            @Value("${app.internal-url:}") String issuerInternalUrl,
            @Value("${app.verifier-internal-url:}") String verifierInternalUrl,
            TenantCustomDomainsLoader tenantCustomDomainsLoader
    ) {
        this.issuerContextPath = normalizeContextPath(issuerContextPath);
        this.verifierContextPath = normalizeContextPath(verifierContextPath);
        this.walletContextPath = normalizeContextPath(walletContextPath);
        this.issuerInternalUrl = stripTrailingSlash(issuerInternalUrl);
        this.verifierInternalUrl = stripTrailingSlash(verifierInternalUrl);
        this.tenantCustomDomainsLoader = tenantCustomDomainsLoader;
    }

    @Override
    public String publicIssuerBaseUrl(ServerWebExchange exchange) {
        return publicOrigin(exchange) + nullToEmpty(issuerContextPath);
    }

    @Override
    public String publicWalletBaseUrl(ServerWebExchange exchange) {
        // Non-canonical topology: the wallet runs on a separate host that cannot
        // be derived from the issuer request origin. Match the request host
        // against the custom-domains registry (issuer host -> wallet URL).
        // We key on the request HOST, not the X-Tenant header: a tenant may be
        // reached through several domains (canonical + custom) and X-Tenant
        // carries the tenant id either way, so it cannot tell which domain was
        // used. The request host can.
        String requestHost = exchange.getRequest().getURI().getHost();
        Optional<String> customWalletUrl = tenantCustomDomainsLoader.findWalletUrlByIssuerHost(requestHost);
        if (customWalletUrl.isPresent()) {
            return stripTrailingSlash(customWalletUrl.get());
        }
        // Canonical topology: issuer and wallet share the same origin (path-based).
        return publicOrigin(exchange) + nullToEmpty(walletContextPath);
    }

    @Override
    public String publicOrigin(ServerWebExchange exchange) {
        URI uri = exchange.getRequest().getURI();
        String scheme = uri.getScheme();
        String host = uri.getHost();
        int port = uri.getPort();
        boolean defaultPort = port == -1
                || ("https".equals(scheme) && port == 443)
                || ("http".equals(scheme) && port == 80);
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(host);
        if (!defaultPort) {
            sb.append(":").append(port);
        }
        return sb.toString();
    }

    @Override
    public List<String> expectedVerifierBaseUrls(ServerWebExchange exchange) {
        String tenantHeader = exchange.getRequest().getHeaders().getFirst(X_TENANT_HEADER);
        if (tenantHeader != null && !tenantHeader.isBlank()) {
            Optional<List<String>> customUrls = tenantCustomDomainsLoader.findVerifierUrls(tenantHeader.trim());
            if (customUrls.isPresent()) {
                return List.copyOf(customUrls.get());
            }
        }
        return List.of(publicOrigin(exchange) + nullToEmpty(verifierContextPath));
    }

    @Override
    public String internalVerifierBaseUrl() {
        return verifierInternalUrl;
    }

    @Override
    public String internalIssuerBaseUrl() {
        return issuerInternalUrl;
    }

    @Override
    public String rewriteToInternalVerifier(String publicAbsoluteUrl) {
        URI publicUri = URI.create(publicAbsoluteUrl);
        URI internalUri = URI.create(verifierInternalUrl);
        String internalOrigin = internalUri.getScheme() + "://" + internalUri.getHost()
                + (internalUri.getPort() == -1 ? "" : ":" + internalUri.getPort());
        // Preserve the public URL's path as-is. The verifier's public paths
        // already include its base-path (e.g. /verifier/oauth2/jwks); the
        // internal base-path is therefore NOT prepended a second time.
        String path = publicUri.getPath() == null ? "" : publicUri.getPath();
        String query = publicUri.getRawQuery();
        return internalOrigin + path + (query != null ? "?" + query : "");
    }

    private static String normalizeContextPath(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String trimmed = raw.trim();
        if (!trimmed.startsWith("/")) {
            trimmed = "/" + trimmed;
        }
        if (trimmed.length() > 1 && trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return "/".equals(trimmed) ? "" : trimmed;
    }

    private static String stripTrailingSlash(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
