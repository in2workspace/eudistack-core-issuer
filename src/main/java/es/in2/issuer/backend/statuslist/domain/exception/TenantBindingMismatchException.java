package es.in2.issuer.backend.statuslist.domain.exception;

/**
 * Thrown when a single-tenant deployment (AD-8, {@code issuer.messaging.revocation.tenant-binding})
 * receives an instruction whose message declares a <b>different</b> tenant than the one
 * configured. Always a permanent error (AC-12): a discordance is evidence the publisher's
 * model of the world does not match the deployment's, so the {@code issuanceId} it carries
 * is suspect too — retrying will not resolve that, and attributing the instruction to the
 * configured tenant anyway would risk revoking the wrong credential.
 */
public class TenantBindingMismatchException extends RuntimeException {

    public TenantBindingMismatchException(String declaredInMessage, String configured) {
        super("Revocation instruction declares tenant '" + declaredInMessage
                + "' but this deployment is bound to '" + configured + "'");
    }
}
