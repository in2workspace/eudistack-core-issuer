package es.in2.issuer.backend.statuslist.infrastructure.messaging.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Wire contract of the revocation-instruction message ({@code revocation-instruction/v1}),
 * technical-design.md §3.3.1. Infrastructure-only — never crosses into application/domain,
 * which consume {@link es.in2.issuer.backend.statuslist.domain.model.RevocationInstruction}
 * instead (via {@link es.in2.issuer.backend.statuslist.infrastructure.messaging.RevocationInstructionMessageMapper}).
 * <p>
 * {@code type} and {@code issuedAt} are diagnostic-only and never used to decide anything.
 * {@code tenantId} is conditionally mandatory (AD-8): required in the default multi-tenant
 * mode, optional when the deployment declares its own tenant via configuration. Unknown
 * fields are ignored (compatibility with a later contract version, EC-06).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RevocationInstructionMessage(
        String type,
        String messageId,
        String tenantId,
        String issuanceId,
        String reason,
        String issuedAt
) {
}
