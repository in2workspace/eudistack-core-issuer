package es.in2.issuer.backend.shared.domain.policy;

import java.util.List;

/**
 * A permitted issuance: the organization the new attestation belongs to -- set here, from the caller
 * or from the organization a tenant administrator indicated, never from the attestation content
 * (FR-07) -- and the actions that permitted it, for the trace.
 */
public record IssuanceAuthorization(
        RecognizedCaller caller,
        String organizationIdentifier,
        List<String> actionIds
) {
    public IssuanceAuthorization {
        actionIds = List.copyOf(actionIds);
    }
}
