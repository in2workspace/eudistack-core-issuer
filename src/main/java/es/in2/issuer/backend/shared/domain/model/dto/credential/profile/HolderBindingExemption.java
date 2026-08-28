package es.in2.issuer.backend.shared.domain.model.dto.credential.profile;

import java.util.Set;

/**
 * The closed list of credential types allowed to carry a {@code cnf} claim without declaring
 * {@code proof_types_supported} -- the scoped exception to ADR-110 (AD-8, EUD-168).
 *
 * <p>ADR-110 makes {@code proof_types_supported} the single signal of holder binding: present means
 * bound and ineligible for direct delivery, absent means unbound and eligible. It follows that an
 * unbound type has no channel through which a holder key could ever arrive, so it can carry no
 * {@code cnf}. For the machine LEARCredential that conclusion is premature: the machine does own a
 * key pair, it simply has no wallet with which to prove possession at the credential endpoint. The
 * business needs those types delivered directly <em>and</em> bound.
 *
 * <p>The types listed here therefore drop both OID4VCI binding fields -- so they stay eligible for
 * direct delivery, per ADR-110 -- while keeping {@code cnf_required: true}, and source their
 * {@code cnf} from the {@code holder_key} supplied in the issuance request body, for every delivery
 * mode rather than the direct one alone: with {@code proof_types_supported} gone no key proof
 * arrives through the wallet flow either, so the request is the only source of a holder key there is.
 *
 * <p>Deliberately a hardcoded list rather than a profile field. A field would be the alternative
 * ADR-110 rejects -- a fourth signal free to contradict the published metadata -- and it would
 * outlive its reason. Two string literals read as what they are: an exception with an expiry date.
 *
 * <h2>Retirement</h2>
 * When machines get a wallet of their own, these types recover {@code proof_types_supported}, stop
 * being eligible for direct delivery, and derive {@code cnf} from the key proof again. Retiring the
 * exception then means restoring both fields in the two profiles and emptying this set -- after
 * which this class, its use in {@link CredentialProfileBindingInvariant} and the holder-key branch
 * in {@code IssuanceWorkflowImpl} can all be deleted.
 *
 * <p><strong>Caveat.</strong> The {@code holder_key} arrives with no proof of possession, so the
 * resulting {@code cnf} is an issuer assertion, not cryptographic evidence (EUD-168 R-7).
 */
public final class HolderBindingExemption {

    private static final Set<String> EXEMPT_CONFIGURATION_IDS = Set.of(
            "learcredential.machine.sd.1",
            "learcredential.machine.w3c.3"
    );

    private HolderBindingExemption() {
    }

    /**
     * {@code true} when this credential type sources its {@code cnf} from the issuance request
     * instead of from an OID4VCI key proof.
     */
    public static boolean isExempt(String credentialConfigurationId) {
        return EXEMPT_CONFIGURATION_IDS.contains(credentialConfigurationId);
    }

}
