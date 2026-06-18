package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UrlResolverImplTest {

    private static UrlResolverImpl resolver(String issuerCtx, String verifierCtx,
                                            String issuerInternal, String verifierInternal) {
        return new UrlResolverImpl(issuerCtx, verifierCtx, issuerInternal, verifierInternal, null);
    }

    private static ServerWebExchange exchangeAt(String url) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(url));
    }

    private static ServerWebExchange exchangeWithTenant(String url, String tenantId) {
        return MockServerWebExchange.from(
                MockServerHttpRequest.get(url).header("X-Tenant", tenantId));
    }

    // ── publicIssuerBaseUrl — canonical (no X-Tenant) ───────────────────────

    @Test
    void publicIssuerBaseUrl_includesSchemeHostAndContextPath() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeAt("https://sandbox-stg.eudistack.net/issuer/api/v1/me");
        assertEquals("https://sandbox-stg.eudistack.net/issuer", r.publicIssuerBaseUrl(ex));
    }

    @Test
    void publicIssuerBaseUrl_omitsDefaultHttpsPort() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeAt("https://sandbox-stg.eudistack.net:443/issuer/foo");
        assertEquals("https://sandbox-stg.eudistack.net/issuer", r.publicIssuerBaseUrl(ex));
    }

    @Test
    void publicIssuerBaseUrl_keepsNonDefaultPort() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeAt("https://sandbox.127.0.0.1.nip.io:4443/issuer/x");
        assertEquals("https://sandbox.127.0.0.1.nip.io:4443/issuer", r.publicIssuerBaseUrl(ex));
    }

    @Test
    void publicIssuerBaseUrl_worksWithBlankContextPath() {
        UrlResolverImpl r = resolver("", "/verifier", "", "");
        ServerWebExchange ex = exchangeAt("https://host.example/anything");
        assertEquals("https://host.example", r.publicIssuerBaseUrl(ex));
    }

    // ── publicIssuerBaseUrl — non-canonical (custom domain, empty context path) ─

    @Test
    void publicIssuerBaseUrl_nonCanonical_emptyContextPath_omitsPrefix() {
        // Non-canonical deployments configure spring.webflux.base-path as empty
        // because the domain itself identifies the service. X-Tenant presence does
        // not affect URL generation — only issuerContextPath does.
        UrlResolverImpl r = resolver("", "/verifier", "", "");
        ServerWebExchange ex = exchangeWithTenant("https://kpmg.eudistack.net/credential", "kpmg");
        assertEquals("https://kpmg.eudistack.net", r.publicIssuerBaseUrl(ex));
    }

    @Test
    void publicIssuerBaseUrl_xTenantPresent_stillIncludesContextPath() {
        // X-Tenant no longer drives URL generation. A canonical deployment that
        // happens to receive X-Tenant (e.g. CloudFront origin header) must still
        // include the configured context path.
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeWithTenant("https://sandbox.stg.eudistack.net/issuer/x", "sandbox");
        assertEquals("https://sandbox.stg.eudistack.net/issuer", r.publicIssuerBaseUrl(ex));
    }

    // ── publicOrigin ─────────────────────────────────────────────────────────

    @Test
    void publicOrigin_returnsOnlySchemeHostPort() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeAt("https://sandbox-stg.eudistack.net/issuer/api/v1/me");
        assertEquals("https://sandbox-stg.eudistack.net", r.publicOrigin(ex));
    }

    // ── expectedVerifierBaseUrl — canonical (no X-Tenant) ───────────────────

    @Test
    void expectedVerifierBaseUrl_composesOriginPlusVerifierContextPath() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeAt("https://sandbox-stg.eudistack.net/issuer/api/v1/me");
        assertEquals("https://sandbox-stg.eudistack.net/verifier", r.expectedVerifierBaseUrl(ex));
    }

    @Test
    void expectedVerifierBaseUrl_respectsCustomVerifierPath() {
        UrlResolverImpl r = resolver("/issuer", "/v", "", "");
        ServerWebExchange ex = exchangeAt("https://host.example/issuer/x");
        assertEquals("https://host.example/v", r.expectedVerifierBaseUrl(ex));
    }

    // ── expectedVerifierBaseUrl — X-Tenant ignored ───────────────────────────

    @Test
    void expectedVerifierBaseUrl_xTenantPresent_stillUsesOriginPlusContextPath() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        ServerWebExchange ex = exchangeWithTenant("https://sandbox.stg.eudistack.net/issuer/x", "sandbox");
        assertEquals("https://sandbox.stg.eudistack.net/verifier", r.expectedVerifierBaseUrl(ex));
    }

    // ── internal URLs ─────────────────────────────────────────────────────────

    @Test
    void internalIssuerBaseUrl_returnsConfiguredValue() {
        UrlResolverImpl r = resolver("/issuer", "/verifier",
                "http://issuer-core.stg.eudistack.local:8080/issuer",
                "http://verifier-core.stg.eudistack.local:8080/verifier");
        assertEquals("http://issuer-core.stg.eudistack.local:8080/issuer", r.internalIssuerBaseUrl());
    }

    @Test
    void internalVerifierBaseUrl_returnsConfiguredValue() {
        UrlResolverImpl r = resolver("/issuer", "/verifier",
                "http://issuer-core:8080/issuer",
                "http://verifier-core:8080/verifier");
        assertEquals("http://verifier-core:8080/verifier", r.internalVerifierBaseUrl());
    }

    @Test
    void internalUrls_stripTrailingSlash() {
        UrlResolverImpl r = resolver("/issuer", "/verifier",
                "http://issuer-core:8080/issuer/",
                "http://verifier-core:8080/verifier/");
        assertEquals("http://issuer-core:8080/issuer", r.internalIssuerBaseUrl());
        assertEquals("http://verifier-core:8080/verifier", r.internalVerifierBaseUrl());
    }

    @Test
    void internalUrls_blankReturnsEmptyString() {
        UrlResolverImpl r = resolver("/issuer", "/verifier", "", "");
        assertEquals("", r.internalIssuerBaseUrl());
        assertEquals("", r.internalVerifierBaseUrl());
    }

    // ── rewriteToInternalVerifier ─────────────────────────────────────────────

    @Test
    void rewriteToInternalVerifier_preservesPublicPathWithBasePath() {
        // Regression for the 3.5.4 double-prefix bug: the public jwks_uri path
        // already contains /verifier/..., and the internal base already ends
        // with /verifier. The rewrite must NOT duplicate /verifier.
        UrlResolverImpl r = resolver("/issuer", "/verifier",
                "http://issuer-core:8080/issuer",
                "http://verifier-core.stg.eudistack.local:8080/verifier");
        String rewritten = r.rewriteToInternalVerifier(
                "https://sandbox-stg.eudistack.net/verifier/oauth2/jwks");
        assertEquals(
                "http://verifier-core.stg.eudistack.local:8080/verifier/oauth2/jwks",
                rewritten);
    }

    @Test
    void rewriteToInternalVerifier_preservesQueryString() {
        UrlResolverImpl r = resolver("/issuer", "/verifier",
                "", "http://verifier-core:8080/verifier");
        String rewritten = r.rewriteToInternalVerifier(
                "https://host.example/verifier/authorize?client_id=abc&scope=openid");
        assertEquals(
                "http://verifier-core:8080/verifier/authorize?client_id=abc&scope=openid",
                rewritten);
    }

    @Test
    void rewriteToInternalVerifier_handlesRootPath() {
        UrlResolverImpl r = resolver("/issuer", "/verifier",
                "", "http://verifier-core:8080");
        String rewritten = r.rewriteToInternalVerifier("https://host.example/");
        assertEquals("http://verifier-core:8080/", rewritten);
    }
}
