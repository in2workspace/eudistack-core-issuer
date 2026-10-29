package es.in2.issuer.backend.shared.domain.policy;

/**
 * A permitted decision: the action, who was recognized and the scope it was granted with. A denied
 * decision is never returned -- it is an error ({@link es.in2.issuer.backend.shared.domain.exception.LearIssuancePolicyException},
 * {@link es.in2.issuer.backend.shared.domain.exception.TenantMismatchException} or, for a resource out
 * of scope, a not-found exception).
 */
public record AuthorizationDecision(
        String actionId,
        RecognizedCaller caller,
        AuthorizationMatrix.Scope scope
) {
    /** True when the caller may act on every organization of the tenant, false when only on its own. */
    public boolean anyOrganization() {
        return scope == AuthorizationMatrix.Scope.ANY_ORGANIZATION || scope == AuthorizationMatrix.Scope.ALLOW;
    }
}
