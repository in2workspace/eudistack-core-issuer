package es.in2.issuer.backend.statuslist.domain.model;

/**
 * Wraps the tenant a single-tenant deployment declares in its own configuration (AD-8),
 * possibly absent (the default, multi-tenant mode). {@link #resolve} is the single point
 * that decides the effective tenant of a revocation instruction — the truth table in
 * technical-design.md §3.3.1:
 *
 * <pre>
 * binding absent | message tenantId absent | Unresolved            (AC-13)
 * binding absent | message tenantId present | FromMessage(msg)     (today's behaviour)
 * binding = T    | message tenantId absent | FromDeployment(T)     (AC-11)
 * binding = T    | message tenantId = T    | FromMessage(T)        (redundant but legitimate)
 * binding = T    | message tenantId != T   | Mismatch(msg, T)      (AC-12)
 * </pre>
 *
 * Obeys what was declared; never infers what was not (AC-13, NFR-S-225-07 — an invariant,
 * not a tunable threshold).
 */
public record RevocationTenantBinding(String declaredTenant) {

    public static RevocationTenantBinding none() {
        return new RevocationTenantBinding(null);
    }

    public static RevocationTenantBinding of(String declaredTenant) {
        return new RevocationTenantBinding(declaredTenant);
    }

    public boolean isDeclared() {
        return declaredTenant != null && !declaredTenant.isBlank();
    }

    public TenantBindingResolution resolve(String messageTenantId) {
        boolean messageHasTenant = messageTenantId != null && !messageTenantId.isBlank();

        if (!isDeclared()) {
            return messageHasTenant
                    ? new TenantBindingResolution.FromMessage(messageTenantId)
                    : new TenantBindingResolution.Unresolved();
        }
        if (!messageHasTenant) {
            return new TenantBindingResolution.FromDeployment(declaredTenant);
        }
        if (messageTenantId.equals(declaredTenant)) {
            return new TenantBindingResolution.FromMessage(messageTenantId);
        }
        return new TenantBindingResolution.Mismatch(messageTenantId, declaredTenant);
    }
}
