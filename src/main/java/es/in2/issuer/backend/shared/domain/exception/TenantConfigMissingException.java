package es.in2.issuer.backend.shared.domain.exception;

/**
 * Thrown when a REQUIRED tenant_config entry is missing for the current tenant.
 * Indicates an incomplete seed of the tenant — operations on this tenant
 * must fail fast with a clear message, but OTHER tenants stay operational.
 */
public class TenantConfigMissingException extends RuntimeException {

    public TenantConfigMissingException(String tenant, String key) {
        super("Missing required tenant_config key '" + key + "' for tenant '" + tenant
                + "'. Run seed-tenants[.stg].sql or populate via config API.");
    }
}
