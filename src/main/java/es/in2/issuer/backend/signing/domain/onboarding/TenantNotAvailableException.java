package es.in2.issuer.backend.signing.domain.onboarding;

/**
 * The tenant is not in {@code public.tenant_registry} or is not active there. It is a rejection like any
 * other for the operator (exit code 2), but it is not audited: the audit API rejects events of an unknown
 * tenant, so the record of this rejection is the stderr reason, the exit code and a log line.
 */
public class TenantNotAvailableException extends OnboardingRejectedException {

    public TenantNotAvailableException(String message) {
        super(RejectionReason.POLICY_DENIED, message);
    }
}
