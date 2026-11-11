package es.in2.issuer.backend.shared.domain.model.requestcontrol;

import java.util.Objects;

/**
 * Who sends a request to a management API, as far as the volume limit and the idempotency care:
 * the organization its attestation represents and whether it is a person or a system (EUD-269).
 *
 * <p>A person is counted on its own; every system of an organization shares the organization's
 * count. The person is never kept in clear: {@code personKey} is a digest of it, so neither the
 * counters nor the idempotency records hold personal data.
 *
 * @param organizationIdentifier the organization of the token (its mandator)
 * @param kind                   person or system
 * @param personKey              digest of the person; {@code null} for a system
 */
public record Requester(String organizationIdentifier, RequesterKind kind, String personKey) {

    public Requester {
        Objects.requireNonNull(organizationIdentifier, "organizationIdentifier");
        Objects.requireNonNull(kind, "kind");
        if (kind == RequesterKind.PERSON && (personKey == null || personKey.isBlank())) {
            throw new IllegalArgumentException("A person requester needs a person key");
        }
        if (kind == RequesterKind.SYSTEM) {
            personKey = null;
        }
    }

    public static Requester system(String organizationIdentifier) {
        return new Requester(organizationIdentifier, RequesterKind.SYSTEM, null);
    }

    public static Requester person(String organizationIdentifier, String personKey) {
        return new Requester(organizationIdentifier, RequesterKind.PERSON, personKey);
    }

    /**
     * What is counted together: the organization for its systems, the person (within its
     * organization) for a person.
     */
    public String countingScope() {
        return kind == RequesterKind.SYSTEM
                ? organizationIdentifier + "|system"
                : organizationIdentifier + "|person|" + personKey;
    }
}
