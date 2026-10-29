package es.in2.issuer.backend.shared.domain.policy;

import es.in2.issuer.backend.shared.domain.model.dto.credential.lear.Power;

import java.util.List;

/**
 * Who is calling, as its verified access token says: the organization its attestation represents
 * (the mandator), the powers of its mandate and the tenant the token was issued for. A person and a
 * system with the same powers are the same caller for every decision (FR-08).
 *
 * <p>The token's {@code sub} is deliberately not kept: the verifier fills it with the mandatee's
 * email, and the caller is what the decision trace records (FR-13 asks who, not their email;
 * conv-quality-security-gates §10.3). The attestation and the token identify it instead.
 *
 * @param tokenId        {@code jti} of the access token
 * @param credentialType {@code credential_type} of the attestation the caller authenticated with
 * @param attestationId  {@code vc.id} of that attestation, when the token carries it (FR-13 evidence)
 */
public record Caller(
        String organizationIdentifier,
        List<Power> powers,
        String tokenTenant,
        String credentialType,
        String tokenId,
        String attestationId
) {
    public Caller {
        powers = powers != null ? List.copyOf(powers) : List.of();
    }

    public Caller(String organizationIdentifier, List<Power> powers, String tokenTenant, String credentialType,
                  String tokenId) {
        this(organizationIdentifier, powers, tokenTenant, credentialType, tokenId, null);
    }
}
