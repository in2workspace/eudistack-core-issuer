package es.in2.issuer.backend.statuslist.domain.model;

/**
 * Outcome of {@link RevocationTenantBinding#resolve(String)} (AD-8). Sealed so that a
 * consumer's {@code switch} over the four cases is exhaustive at compile time — the
 * invariant this type exists to protect (AC-13, NFR-S-225-07) is that no fifth,
 * silently-inferred case can ever be added without every switch site failing to compile.
 */
public sealed interface TenantBindingResolution {

    /** The effective tenant came from the message's own {@code tenantId} field. */
    record FromMessage(String tenantId) implements TenantBindingResolution {
    }

    /** The message declared no tenant; the deployment's configured binding was used (AC-11). */
    record FromDeployment(String tenantId) implements TenantBindingResolution {
    }

    /** The deployment declared a tenant and the message declared a different one (AC-12). */
    record Mismatch(String declaredInMessage, String configured) implements TenantBindingResolution {
    }

    /** Neither the message nor the deployment declared a tenant (AC-13) — never inferred. */
    record Unresolved() implements TenantBindingResolution {
    }
}
