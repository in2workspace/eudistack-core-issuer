package es.in2.issuer.backend.shared.domain.util;

/**
 * Shared normalization for tenant identifiers resolved from an environment-specific source
 * (request host, a revocation-instruction message) before they are checked against
 * {@code tenant_registry}. Originally private to {@code TenantDomainWebFilter}; extracted so
 * every entry point applies the exact same criterion (F5, EUD-225 {@code /verify}).
 */
public final class TenantIdentifiers {

    // Environment suffixes appended to tenant identifiers in non-prod DNS
    // (e.g. sandbox-stg.eudistack.net, platform-dev.eudistack.net). Stripped before the
    // registry lookup so tenant schemas stay environment-agnostic.
    private static final String[] ENV_SUFFIXES = {"-stg", "-dev", "-pre"};

    private TenantIdentifiers() {
    }

    public static String stripEnvSuffix(String tenant) {
        if (tenant == null) {
            return null;
        }
        for (String suffix : ENV_SUFFIXES) {
            if (tenant.endsWith(suffix)) {
                return tenant.substring(0, tenant.length() - suffix.length());
            }
        }
        return tenant;
    }
}
