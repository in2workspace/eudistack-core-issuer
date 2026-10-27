package es.in2.issuer.backend.signing.domain.spi;

/** Who runs the onboarding tool, as the cloud provider authenticates it. */
public interface CallerIdentityPort {

    /**
     * The ARN of the caller (with SSO, {@code assumed-role/<role>/<person>}). It is what
     * {@code activated_by} and {@code withdrawn_by} record: never free text.
     */
    String callerArn();
}
