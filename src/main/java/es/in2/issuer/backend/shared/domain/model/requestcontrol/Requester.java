package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.util.Objects;

/**
 * Who sends a request to a management API, as far as the volume limit and the idempotency care:
 * the organization its attestation represents, whether it is a person or a system, and which one
 * (EUD-269).
 *
 * <p>A person is counted on its own; every system of an organization shares the organization's
 * count. The idempotency keys, instead, belong to each caller, the systems included, so two systems
 * of one organization that send the same key never share a response. The caller is never kept in
 * clear: {@code callerKey} is a pseudonym of it, so neither the counters nor the idempotency records
 * hold personal data.
 *
 * @param organizationIdentifier the organization of the token (its mandator)
 * @param kind                   person or system
 * @param callerKey              pseudonym of the person or of the system; required for a person,
 *                               {@code null} for a system the token does not name
 */
public record Requester(String organizationIdentifier, RequesterKind kind, String callerKey) {

    public Requester {
        Objects.requireNonNull(organizationIdentifier, "organizationIdentifier");
        Objects.requireNonNull(kind, "kind");
        if (kind == RequesterKind.PERSON && (callerKey == null || callerKey.isBlank())) {
            throw new IllegalArgumentException("A person requester needs a caller key");
        }
        if (callerKey != null && callerKey.isBlank()) {
            callerKey = null;
        }
    }

    public static Requester system(String organizationIdentifier) {
        return new Requester(organizationIdentifier, RequesterKind.SYSTEM, null);
    }

    public static Requester system(String organizationIdentifier, String callerKey) {
        return new Requester(organizationIdentifier, RequesterKind.SYSTEM, callerKey);
    }

    public static Requester person(String organizationIdentifier, String callerKey) {
        return new Requester(organizationIdentifier, RequesterKind.PERSON, callerKey);
    }

    /**
     * What is counted together: the organization for its systems, the person (within its
     * organization) for a person.
     */
    public String countingScope() {
        return kind == RequesterKind.SYSTEM
                ? organizationIdentifier + "|system"
                : organizationIdentifier + "|person|" + callerKey;
    }

    /** Whose idempotency keys these are: the caller itself, also when it is one system of the organization. */
    public String idempotencyScope() {
        return kind == RequesterKind.SYSTEM && callerKey != null
                ? countingScope() + "|" + callerKey
                : countingScope();
    }
}
